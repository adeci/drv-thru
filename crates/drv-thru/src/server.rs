use std::{
    collections::BTreeSet,
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use tokio::{io::AsyncReadExt, sync::Semaphore, task::JoinSet};

use crate::{
    access::AccessPolicy,
    cache,
    config::{DEFAULT_MAX_CONCURRENT_BUILDS, load_server_config, parse_byte_count, parse_duration},
    keys, nix,
    proto::{
        ALPN, AuthOk, BuildFinished, BuildRequest, CacheFileResponse, ErrorMessage, Message,
        NixLog, OutputCacheReady, OutputMode, PathListChunk, VERSION,
    },
    ticket::{self, TicketStore},
    wire,
};

const PATH_CHUNK_SIZE: usize = 512;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_NIX_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

pub enum ServeMode {
    DataDir {
        data_dir: PathBuf,
        trusted_clients: Vec<EndpointId>,
    },
    Config(PathBuf),
}

struct CheckedBuildRequest {
    drv_path: nix::StorePath,
    output_mode: OutputMode,
    closure_paths: Vec<nix::StorePath>,
    output_paths: Vec<nix::StorePath>,
}

struct FinishedBuild {
    success: bool,
    output_paths: Vec<nix::StorePath>,
}

struct AuthorizedConnection {
    max_build_time: Option<Duration>,
    max_upload_bytes: Option<u64>,
}

pub async fn serve(mode: ServeMode) -> Result<()> {
    let (data_dir, secret_key_file, access_policy, max_concurrent_builds) = match mode {
        ServeMode::DataDir {
            data_dir,
            trusted_clients,
        } => (
            data_dir,
            None,
            AccessPolicy::from_endpoint_ids(trusted_clients),
            DEFAULT_MAX_CONCURRENT_BUILDS,
        ),
        ServeMode::Config(path) => {
            let config = load_server_config(&path)?;
            let access_policy = AccessPolicy::from_config(&config)?;
            (
                config.data_dir,
                config.secret_key_file,
                access_policy,
                config.max_concurrent_builds,
            )
        }
    };

    let signing_key = Arc::new(keys::load_or_create_signing_key(&data_dir)?);
    let key_path = secret_key_file.unwrap_or_else(|| keys::server_key_path(&data_dir));
    let key = keys::load_or_create(key_path)?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await?;

    println!("server endpoint id: {}", endpoint.id());
    endpoint.online().await;

    let addr = endpoint.addr();
    for relay_url in addr.relay_urls() {
        println!("server relay url: {relay_url}");
    }
    for direct_addr in addr.ip_addrs() {
        println!("server direct addr: {direct_addr}");
    }
    ticket::save_server_addr(&data_dir, &addr)?;

    let ticket_store = TicketStore::new(&data_dir);
    ticket_store.load()?;
    let build_queue = Arc::new(Semaphore::new(max_concurrent_builds));

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let access_policy = access_policy.clone();
                let ticket_store = ticket_store.clone();
                let build_queue = build_queue.clone();
                let signing_key = signing_key.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(conn) => conn,
                        Err(err) => {
                            eprintln!("connection error: {err:#}");
                            return;
                        }
                    };

                    if let Err(err) = handle_incoming(conn, access_policy, ticket_store, build_queue, signing_key).await {
                        eprintln!("connection error: {err:#}");
                    }
                });
            }
        }
    }

    endpoint.close().await;
    Ok(())
}

async fn handle_incoming(
    conn: Connection,
    access_policy: AccessPolicy,
    ticket_store: TicketStore,
    build_queue: Arc<Semaphore>,
    signing_key: Arc<keys::SigningKey>,
) -> Result<()> {
    let peer = conn.remote_id();
    let (mut send, mut recv) = conn.accept_bi().await?;

    match read_message(&mut recv).await? {
        Message::Hello(hello) => {
            if hello.version != VERSION {
                bail!("unsupported protocol version: {}", hello.version);
            }

            let claimed_peer: EndpointId = hello
                .node_id
                .parse()
                .with_context(|| format!("parse hello node id: {}", hello.node_id))?;
            if claimed_peer != peer {
                bail!("hello node id {claimed_peer} does not match connection peer {peer}");
            }
        }
        message => bail!("expected hello, got {message:?}"),
    }

    let Some(authorized) =
        authorize_connection(&peer, &access_policy, &ticket_store, &mut send, &mut recv).await?
    else {
        send.finish()?;
        wait_closed(&conn).await;
        return Ok(());
    };

    let build = match read_message_with_timeout(&mut recv, CLIENT_NIX_TIMEOUT).await? {
        Message::BuildRequest(request) => {
            let build = read_path_chunks_with_timeout(
                &mut recv,
                PathListKind::BuildPaths,
                CLIENT_NIX_TIMEOUT,
            )
            .await
            .and_then(|closure_paths| handle_build_request(request, closure_paths));
            match build {
                Ok(build) => build,
                Err(err) => {
                    send_error(&mut send, &err.to_string()).await?;
                    send.finish()?;
                    wait_closed(&conn).await;
                    return Ok(());
                }
            }
        }
        message => bail!("expected build request, got {message:?}"),
    };

    wire::write_json(&mut send, &Message::BuildQueued).await?;

    let build_result = {
        let _permit = match build_queue.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                send_error(&mut send, "build queue is closed").await?;
                send.finish()?;
                wait_closed(&conn).await;
                return Ok(());
            }
        };
        run_queued_build(&conn, &mut send, &mut recv, build, authorized, &signing_key).await
    };

    if let Err(err) = build_result {
        send_error(&mut send, &err.to_string()).await?;
    }
    send.finish()?;

    wait_closed(&conn).await;
    Ok(())
}

async fn authorize_connection(
    peer: &EndpointId,
    access_policy: &AccessPolicy,
    ticket_store: &TicketStore,
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<Option<AuthorizedConnection>> {
    match read_message(recv).await? {
        Message::AuthTrustedClient => authorize_trusted_client(peer, access_policy, send).await,
        Message::AuthTicket(auth) => authorize_ticket(peer, ticket_store, send, &auth.secret).await,
        message => {
            send_error(send, &format!("expected auth message, got {message:?}")).await?;
            Ok(None)
        }
    }
}

async fn authorize_trusted_client(
    peer: &EndpointId,
    access_policy: &AccessPolicy,
    send: &mut SendStream,
) -> Result<Option<AuthorizedConnection>> {
    let Some(client) = access_policy.authorize(peer) else {
        send_error(send, "client is not trusted").await?;
        return Ok(None);
    };

    match &client.name {
        Some(name) => println!("accepted trusted client {name} ({peer})"),
        None => println!("accepted trusted client {peer}"),
    }

    let max_build_time = client
        .policy
        .max_build_time
        .as_deref()
        .map(parse_duration)
        .transpose()?;
    let max_upload_bytes = client
        .policy
        .max_upload_bytes
        .as_deref()
        .map(parse_byte_count)
        .transpose()?;

    wire::write_json(
        send,
        &Message::AuthOk(AuthOk {
            client_name: client.name,
        }),
    )
    .await?;

    Ok(Some(AuthorizedConnection {
        max_build_time,
        max_upload_bytes,
    }))
}

async fn authorize_ticket(
    peer: &EndpointId,
    ticket_store: &TicketStore,
    send: &mut SendStream,
    secret: &[u8; 32],
) -> Result<Option<AuthorizedConnection>> {
    let record = match ticket_store.redeem(secret, peer) {
        Ok(record) => record,
        Err(err) => {
            send_error(send, &err.to_string()).await?;
            return Ok(None);
        }
    };

    match &record.name {
        Some(name) => println!("accepted ticket {name} ({peer})"),
        None => println!("accepted ticket ({peer})"),
    }

    let max_build_time = Some(parse_duration(&record.max_build_time)?);
    let max_upload_bytes = Some(parse_byte_count(&record.max_upload_bytes)?);

    wire::write_json(
        send,
        &Message::AuthOk(AuthOk {
            client_name: record.name,
        }),
    )
    .await?;

    Ok(Some(AuthorizedConnection {
        max_build_time,
        max_upload_bytes,
    }))
}

fn handle_build_request(
    request: BuildRequest,
    closure_paths: Vec<String>,
) -> Result<CheckedBuildRequest> {
    println!(
        "build requested: {} ({:?})",
        request.installable, request.output_mode
    );

    let drv_path = nix::StorePath::new(request.drv_path)?;
    let output_paths = request
        .output_paths
        .into_iter()
        .map(nix::StorePath::new)
        .collect::<Result<Vec<_>>>()?;
    if output_paths.is_empty() {
        bail!("build request did not include output paths");
    }

    let mut closure_paths = closure_paths
        .into_iter()
        .map(nix::StorePath::new)
        .collect::<Result<Vec<_>>>()?;

    if !closure_paths.iter().any(|path| path == &drv_path) {
        closure_paths.push(drv_path.clone());
    }

    Ok(CheckedBuildRequest {
        drv_path,
        output_mode: request.output_mode,
        closure_paths,
        output_paths,
    })
}

async fn run_queued_build(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    build: CheckedBuildRequest,
    authorized: AuthorizedConnection,
    signing_key: &keys::SigningKey,
) -> Result<()> {
    let missing_paths = nix::missing_paths(&build.closure_paths).await?;
    println!(
        "drv path: {}, checked paths: {}, missing paths: {}",
        build.drv_path.as_str(),
        build.closure_paths.len(),
        missing_paths.len()
    );

    write_path_chunks(
        send,
        &store_paths_to_strings(&missing_paths),
        Message::MissingPaths,
    )
    .await?;

    if !missing_paths.is_empty() {
        import_missing_inputs(conn, send, &missing_paths, authorized.max_upload_bytes).await?;
    }

    let finished = run_build(
        send,
        &build.drv_path,
        build.output_mode,
        authorized.max_build_time,
        &build.output_paths,
    )
    .await?;
    if finished.success {
        export_outputs(conn, send, recv, &finished.output_paths, signing_key).await?;
    }

    Ok(())
}

async fn run_build(
    send: &mut SendStream,
    drv_path: &nix::StorePath,
    output_mode: OutputMode,
    max_build_time: Option<Duration>,
    requested_outputs: &[nix::StorePath],
) -> Result<FinishedBuild> {
    wire::write_json(send, &Message::BuildStarted).await?;

    let mut log_sink = WireLogSink { send };
    let build = nix::realise(drv_path, output_mode, &mut log_sink);
    let result = match max_build_time {
        Some(max_build_time) => tokio::time::timeout(max_build_time, build)
            .await
            .context("build timed out")??,
        None => build.await?,
    };
    let success = result.success;
    let output_paths = if success {
        selected_outputs(requested_outputs, &result.output_paths)?
    } else {
        Vec::new()
    };
    let output_path_strings = output_paths
        .iter()
        .map(|path| path.as_str().to_string())
        .collect();

    wire::write_json(
        &mut *log_sink.send,
        &Message::BuildFinished(BuildFinished {
            success,
            output_paths: output_path_strings,
        }),
    )
    .await?;

    Ok(FinishedBuild {
        success,
        output_paths,
    })
}

fn selected_outputs(
    requested_outputs: &[nix::StorePath],
    all_outputs: &[nix::StorePath],
) -> Result<Vec<nix::StorePath>> {
    let all_outputs = all_outputs
        .iter()
        .map(|path| path.as_str().to_string())
        .collect::<BTreeSet<_>>();
    let mut selected = Vec::new();
    for output in requested_outputs {
        if !all_outputs.contains(output.as_str()) {
            bail!("requested output was not realised: {}", output.as_str());
        }
        selected.push(output.clone());
    }
    Ok(selected)
}

async fn export_outputs(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    output_paths: &[nix::StorePath],
    signing_key: &keys::SigningKey,
) -> Result<()> {
    let closure = nix::output_closure(output_paths).await?;
    write_path_chunks(
        send,
        &store_paths_to_strings(&closure),
        Message::OutputClosure,
    )
    .await?;

    let requested =
        read_path_chunks_with_timeout(recv, PathListKind::OutputRequest, CLIENT_NIX_TIMEOUT)
            .await
            .and_then(|request| requested_output_paths(request, &closure))?;

    if requested.is_empty() {
        return wire::write_json(send, &Message::Done).await;
    }

    let cache_dir = TempCacheDir::new()?;
    nix::copy_to_signed_binary_cache(&requested, cache_dir.path(), &signing_key.secret_path)
        .await?;

    wire::write_json(
        send,
        &Message::OutputCacheReady(OutputCacheReady {
            public_key: signing_key.public_key.clone(),
            copy_paths: store_paths_to_strings(&requested),
        }),
    )
    .await?;

    serve_output_cache(conn, recv, cache_dir.path()).await?;
    wire::write_json(send, &Message::Done).await
}

async fn serve_output_cache(
    conn: &Connection,
    recv: &mut RecvStream,
    cache_dir: &Path,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            message = wire::read_json::<Message>(recv) => {
                match message? {
                    Message::OutputCacheDone => break,
                    Message::Error(err) => bail!("{}", err.message),
                    message => bail!("unexpected output cache message: {message:?}"),
                }
            }
            accepted = conn.accept_bi() => {
                let (send, recv) = accepted.context("accept cache file stream")?;
                let cache_dir = cache_dir.to_path_buf();
                tasks.spawn(async move { handle_cache_file_stream(send, recv, cache_dir).await });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                result.context("cache file task panicked")???;
            }
        }
    }

    while let Some(result) = tasks.join_next().await {
        result.context("cache file task panicked")??;
    }
    Ok(())
}

async fn handle_cache_file_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    cache_dir: PathBuf,
) -> Result<()> {
    let request = match read_message_with_timeout(&mut recv, CONTROL_TIMEOUT).await? {
        Message::CacheFileRequest(request) => request,
        message => bail!("unexpected cache file request: {message:?}"),
    };

    let path = cache::cache_file_path(&cache_dir, &request.path)?;
    let file = match tokio::fs::File::open(&path).await {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            write_cache_file_response(&mut send, false, 0).await?;
            send.finish()?;
            return Ok(());
        }
        Err(err) => return Err(err).with_context(|| format!("open {}", path.display())),
    };

    let byte_count = file
        .metadata()
        .await
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    write_cache_file_response(&mut send, true, byte_count).await?;

    if request.send_body {
        let mut body = file.take(byte_count);
        let copied = tokio::io::copy(&mut body, &mut send)
            .await
            .with_context(|| format!("stream {}", path.display()))?;
        if copied != byte_count {
            bail!("short cache file read: {copied} of {byte_count} bytes");
        }
    }

    send.finish()?;
    Ok(())
}

async fn write_cache_file_response(
    send: &mut SendStream,
    found: bool,
    byte_count: u64,
) -> Result<()> {
    wire::write_json(
        send,
        &Message::CacheFileResponse(CacheFileResponse { found, byte_count }),
    )
    .await
}

struct TempCacheDir {
    path: PathBuf,
}

impl TempCacheDir {
    fn new() -> Result<Self> {
        let base = std::env::temp_dir();
        fs::create_dir_all(&base).with_context(|| format!("create {}", base.display()))?;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        for attempt in 0..100 {
            let path = base.join(format!(
                "drv-thru-cache-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err).with_context(|| format!("create {}", path.display())),
            }
        }

        bail!("failed to create temporary output cache directory")
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempCacheDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn requested_output_paths(
    request: Vec<String>,
    allowed_paths: &[nix::StorePath],
) -> Result<Vec<nix::StorePath>> {
    let allowed = allowed_paths
        .iter()
        .map(|path| path.as_str().to_string())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut requested = Vec::new();

    for path in request {
        let path = nix::StorePath::new(path)?;
        if !allowed.contains(path.as_str()) {
            bail!("requested output path was not built: {}", path.as_str());
        }
        if seen.insert(path.as_str().to_string()) {
            requested.push(path);
        }
    }

    Ok(requested)
}

struct WireLogSink<'a> {
    send: &'a mut SendStream,
}

impl nix::LogSink for WireLogSink<'_> {
    async fn log_line(&mut self, line: String) -> Result<()> {
        wire::write_json(&mut *self.send, &Message::NixLog(NixLog { line })).await
    }
}

async fn import_missing_inputs(
    conn: &Connection,
    send: &mut SendStream,
    missing_paths: &[nix::StorePath],
    max_upload_bytes: Option<u64>,
) -> Result<()> {
    wire::write_json(send, &Message::InputUploadReady).await?;

    let mut recv = tokio::time::timeout(CONTROL_TIMEOUT, conn.accept_uni())
        .await
        .context("input upload timed out")??;
    tokio::time::timeout(
        UPLOAD_TIMEOUT,
        nix::import_unsigned_export_stream(&mut recv, max_upload_bytes),
    )
    .await
    .context("input upload timed out")??;

    let still_missing = nix::missing_paths(missing_paths).await?;
    if !still_missing.is_empty() {
        bail!("missing paths after import: {}", still_missing.len());
    }

    Ok(())
}

async fn write_path_chunks(
    send: &mut SendStream,
    paths: &[String],
    make_message: fn(PathListChunk) -> Message,
) -> Result<()> {
    if paths.is_empty() {
        wire::write_json(
            send,
            &make_message(PathListChunk {
                paths: Vec::new(),
                done: true,
            }),
        )
        .await?;
        return Ok(());
    }

    let last_index = paths.chunks(PATH_CHUNK_SIZE).len().saturating_sub(1);
    for (index, chunk) in paths.chunks(PATH_CHUNK_SIZE).enumerate() {
        wire::write_json(
            send,
            &make_message(PathListChunk {
                paths: chunk.to_vec(),
                done: index == last_index,
            }),
        )
        .await?;
    }
    Ok(())
}

async fn read_path_chunks_with_timeout(
    recv: &mut RecvStream,
    kind: PathListKind,
    timeout: Duration,
) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    loop {
        let chunk = match read_message_with_timeout(recv, timeout).await? {
            Message::BuildPaths(chunk) if matches!(kind, PathListKind::BuildPaths) => chunk,
            Message::OutputRequest(chunk) if matches!(kind, PathListKind::OutputRequest) => chunk,
            Message::Error(err) => bail!("{}", err.message),
            message => bail!("unexpected path list message: {message:?}"),
        };
        paths.extend(chunk.paths);
        if chunk.done {
            return Ok(paths);
        }
    }
}

fn store_paths_to_strings(paths: &[nix::StorePath]) -> Vec<String> {
    paths.iter().map(|path| path.as_str().to_string()).collect()
}

enum PathListKind {
    BuildPaths,
    OutputRequest,
}

async fn wait_closed(conn: &Connection) {
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, conn.closed()).await;
}

async fn send_error(send: &mut SendStream, message: &str) -> Result<()> {
    wire::write_json(
        send,
        &Message::Error(ErrorMessage {
            message: message.to_string(),
        }),
    )
    .await
}

async fn read_message(recv: &mut RecvStream) -> Result<Message> {
    read_message_with_timeout(recv, CONTROL_TIMEOUT).await
}

async fn read_message_with_timeout(recv: &mut RecvStream, timeout: Duration) -> Result<Message> {
    tokio::time::timeout(timeout, wire::read_json(recv))
        .await
        .context("read timed out")?
}
