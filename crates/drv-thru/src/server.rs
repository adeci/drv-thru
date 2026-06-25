use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{Mutex, Semaphore},
    task::JoinSet,
};

use crate::{
    access::AccessPolicy,
    cache,
    config::{
        DEFAULT_MAX_CONCURRENT_BUILDS, DEFAULT_RECENT_BUILDS_LIMIT, MAX_AUTO_CACHE_FILLS,
        load_server_config, parse_byte_count, parse_duration,
    },
    keys, nix,
    proto::{
        ALPN, AuthOk, BuildFinished, BuildRequest, CacheFileResponse, ErrorMessage, Message,
        NixLog, OutputCacheReady, OutputMode, PathListChunk, VERSION,
    },
    ticket::{self, TicketStore},
    wire,
};

mod output_cache;
pub(crate) mod status;

const PATH_CHUNK_SIZE: usize = 512;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_NIX_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const UPLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

fn default_output_cache_max_parallel_fills() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(1, MAX_AUTO_CACHE_FILLS)
}

pub enum ServeMode {
    DataDir {
        data_dir: PathBuf,
        trusted_clients: Vec<EndpointId>,
    },
    Config(PathBuf),
}

struct CheckedBuildRequest {
    installable: String,
    drv_path: nix::StorePath,
    output_mode: OutputMode,
    rebuild: bool,
    closure_paths: Vec<nix::StorePath>,
    output_paths: Vec<nix::StorePath>,
}

struct FinishedBuild {
    success: bool,
    output_paths: Vec<nix::StorePath>,
}

struct AuthorizedConnection {
    client_label: String,
    max_build_time: Option<Duration>,
    max_upload_bytes: Option<u64>,
    ticket_secret: Option<[u8; 32]>,
}

struct BuildStatusScope<'a> {
    registry: &'a status::StatusRegistry,
    request_id: &'a str,
}

pub async fn serve(mode: ServeMode) -> Result<()> {
    let (
        data_dir,
        secret_key_file,
        access_policy,
        max_concurrent_builds,
        output_cache_max_parallel_fills,
        recent_builds_limit,
    ) = match mode {
        ServeMode::DataDir {
            data_dir,
            trusted_clients,
        } => (
            data_dir,
            None,
            AccessPolicy::from_endpoint_ids(trusted_clients),
            DEFAULT_MAX_CONCURRENT_BUILDS,
            None,
            DEFAULT_RECENT_BUILDS_LIMIT,
        ),
        ServeMode::Config(path) => {
            let config = load_server_config(&path)?;
            let access_policy = AccessPolicy::from_config(&config)?;
            (
                config.data_dir,
                config.secret_key_file,
                access_policy,
                config.max_concurrent_builds,
                config.output_cache_max_parallel_fills,
                config.recent_builds_limit,
            )
        }
    };

    let signing_key = Arc::new(keys::load_or_create_signing_key(&data_dir)?);
    let output_cache_max_parallel_fills =
        output_cache_max_parallel_fills.unwrap_or_else(default_output_cache_max_parallel_fills);
    println!("output cache max parallel fills: {output_cache_max_parallel_fills}");
    let output_cache = Arc::new(output_cache::OutputCache::new(
        &data_dir,
        signing_key,
        output_cache_max_parallel_fills,
    )?);
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

    let status = status::StatusRegistry::new(
        &data_dir,
        endpoint.id().to_string(),
        max_concurrent_builds,
        recent_builds_limit,
    )?;
    let status_heartbeat = tokio::spawn(status.clone().heartbeat());
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
                let output_cache = output_cache.clone();
                let status = status.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(conn) => conn,
                        Err(err) => {
                            eprintln!("connection error: {err:#}");
                            return;
                        }
                    };

                    if let Err(err) = handle_incoming(conn, access_policy, ticket_store, build_queue, output_cache, status).await {
                        eprintln!("connection error: {err:#}");
                    }
                });
            }
        }
    }

    status_heartbeat.abort();
    endpoint.close().await;
    Ok(())
}

async fn handle_incoming(
    conn: Connection,
    access_policy: AccessPolicy,
    ticket_store: TicketStore,
    build_queue: Arc<Semaphore>,
    output_cache: Arc<output_cache::OutputCache>,
    status_registry: status::StatusRegistry,
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

    let Some(authorized) = authorize_connection(
        &peer,
        &access_policy,
        &ticket_store,
        &mut send,
        &mut recv,
        output_cache.public_key(),
    )
    .await?
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

    let Some(authorized) =
        redeem_ticket_if_needed(authorized, &peer, &ticket_store, &mut send).await?
    else {
        send.finish()?;
        wait_closed(&conn).await;
        return Ok(());
    };

    let request_id =
        status_registry.enqueue(authorized.client_label.clone(), build.installable.clone());
    if let Err(err) = wire::write_json(&mut send, &Message::BuildQueued).await {
        status_registry.finish(
            &request_id,
            status::BuildResult::Error,
            Some(err.to_string()),
        );
        return Err(err);
    }

    let build_result = {
        let _permit = match build_queue.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                status_registry.finish(
                    &request_id,
                    status::BuildResult::Error,
                    Some("build queue is closed".to_string()),
                );
                send_error(&mut send, "build queue is closed").await?;
                send.finish()?;
                wait_closed(&conn).await;
                return Ok(());
            }
        };
        status_registry.start(&request_id);
        run_queued_build(
            &conn,
            &mut send,
            &mut recv,
            build,
            authorized,
            output_cache.as_ref(),
            BuildStatusScope {
                registry: &status_registry,
                request_id: &request_id,
            },
        )
        .await
    };

    match build_result {
        Ok(true) => status_registry.finish(&request_id, status::BuildResult::Success, None),
        Ok(false) => status_registry.finish(
            &request_id,
            status::BuildResult::Failed,
            Some("nix build failed".to_string()),
        ),
        Err(err) => {
            let message = err.to_string();
            status_registry.finish(
                &request_id,
                status::BuildResult::Error,
                Some(message.clone()),
            );
            send_error(&mut send, &message).await?;
        }
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
    builder_public_key: &str,
) -> Result<Option<AuthorizedConnection>> {
    match read_message(recv).await? {
        Message::AuthTrustedClient => {
            authorize_trusted_client(peer, access_policy, send, builder_public_key).await
        }
        Message::AuthTicket(auth) => {
            authorize_ticket(peer, ticket_store, send, &auth.secret, builder_public_key).await
        }
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
    builder_public_key: &str,
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

    let client_name = client.name.clone();
    let client_label = client
        .name
        .as_deref()
        .map(|name| format!("client:{name}"))
        .unwrap_or_else(|| format!("client:{peer}"));

    wire::write_json(
        send,
        &Message::AuthOk(AuthOk {
            client_name,
            builder_public_key: builder_public_key.to_string(),
        }),
    )
    .await?;

    Ok(Some(AuthorizedConnection {
        client_label,
        max_build_time,
        max_upload_bytes,
        ticket_secret: None,
    }))
}

async fn authorize_ticket(
    peer: &EndpointId,
    ticket_store: &TicketStore,
    send: &mut SendStream,
    secret: &[u8; 32],
    builder_public_key: &str,
) -> Result<Option<AuthorizedConnection>> {
    let record = match ticket_store.check(secret, peer) {
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

    let client_name = record.name.clone();
    let client_label = record
        .name
        .as_deref()
        .map(|name| format!("ticket:{name}"))
        .unwrap_or_else(|| format!("ticket:{peer}"));

    wire::write_json(
        send,
        &Message::AuthOk(AuthOk {
            client_name,
            builder_public_key: builder_public_key.to_string(),
        }),
    )
    .await?;

    Ok(Some(AuthorizedConnection {
        client_label,
        max_build_time,
        max_upload_bytes,
        ticket_secret: Some(*secret),
    }))
}

async fn redeem_ticket_if_needed(
    mut authorized: AuthorizedConnection,
    peer: &EndpointId,
    ticket_store: &TicketStore,
    send: &mut SendStream,
) -> Result<Option<AuthorizedConnection>> {
    let Some(secret) = authorized.ticket_secret.take() else {
        return Ok(Some(authorized));
    };

    let record = match ticket_store.redeem(&secret, peer) {
        Ok(record) => record,
        Err(err) => {
            send_error(send, &err.to_string()).await?;
            return Ok(None);
        }
    };

    authorized.max_build_time = Some(parse_duration(&record.max_build_time)?);
    authorized.max_upload_bytes = Some(parse_byte_count(&record.max_upload_bytes)?);
    Ok(Some(authorized))
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
        installable: request.installable,
        drv_path,
        output_mode: request.output_mode,
        rebuild: request.rebuild,
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
    output_cache: &output_cache::OutputCache,
    status: BuildStatusScope<'_>,
) -> Result<bool> {
    status.registry.phase(status.request_id, "checking inputs");
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
        status.registry.phase(status.request_id, "uploading inputs");
        import_missing_inputs(conn, send, &missing_paths, authorized.max_upload_bytes).await?;
    }

    status.registry.phase(
        status.request_id,
        if build.rebuild {
            "rebuilding"
        } else {
            "building"
        },
    );
    let finished = run_build(
        send,
        &build.drv_path,
        build.output_mode,
        build.rebuild,
        authorized.max_build_time,
        &build.output_paths,
    )
    .await?;
    if finished.success {
        status
            .registry
            .phase(status.request_id, "serving output cache");
        output_cache::export_outputs(conn, send, recv, &finished.output_paths, output_cache)
            .await?;
    }

    Ok(finished.success)
}

async fn run_build(
    send: &mut SendStream,
    drv_path: &nix::StorePath,
    output_mode: OutputMode,
    rebuild: bool,
    max_build_time: Option<Duration>,
    requested_outputs: &[nix::StorePath],
) -> Result<FinishedBuild> {
    wire::write_json(send, &Message::BuildStarted).await?;

    let mut log_sink = WireLogSink { send };
    let build = nix::realise(drv_path, output_mode, rebuild, &mut log_sink);
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
