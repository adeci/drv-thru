use std::{path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use iroh::{
    Endpoint, EndpointId, SecretKey,
    endpoint::{Connection, RecvStream, SendStream, presets},
};

use crate::{
    client_cache,
    client_status::{ClientStatus, ProgressWriter},
    keys, nix,
    protocol::{
        ALPN, AuthTicket, BuildFinished, BuildRequest, Hello, Message, OutputMode, VERSION,
        path_chunks::{self, PathListKind, ReadLimits},
        wire,
    },
};

use super::{
    BuildAuth,
    logs::LogRenderer,
    summary::{self, BuildSummary},
};

const SERVER_PATH_LIST_TIMEOUT: Duration = Duration::from_mins(10);
const SERVER_PATH_LIST_LIMITS: ReadLimits = ReadLimits {
    chunks: 512,
    paths: 100_000,
    bytes: 16 * 1024 * 1024,
};

struct RequestedOutputs {
    paths: Vec<nix::StorePath>,
    strings: Vec<String>,
}

struct PreparedBuild {
    drv_path: nix::StorePath,
    closure_path_count: usize,
    closure_path_strings: Vec<String>,
}

struct RemoteBuildResult {
    missing_path_count: usize,
    build_success: bool,
    output_paths: Vec<String>,
    received_bytes: u64,
}

struct ConnectedSession {
    endpoint: Endpoint,
    conn: Connection,
    send: SendStream,
    recv: RecvStream,
    server_id: EndpointId,
    builder_public_key: String,
    _key_file_lock: Option<keys::KeyFileLock>,
}

pub(super) async fn build(
    installable: String,
    auth: Option<BuildAuth>,
    key_file: Option<PathBuf>,
    output_mode: OutputMode,
    nar_fetches: Option<usize>,
    eval_options: nix::EvalOptions,
    rebuild: bool,
) -> Result<()> {
    let mut status = ClientStatus::new();
    let installable_label = installable.clone();
    let requested_outputs =
        resolve_requested_outputs(&mut status, &installable_label, &eval_options).await?;

    if local_outputs_present(&requested_outputs.paths, rebuild, &mut status).await? {
        status.clear_phase();
        summary::print_local_outputs(&status, &installable_label, &requested_outputs.strings);
        return Ok(());
    }

    let auth = auth.context(
        "build requires either --server or --ticket when requested outputs are missing locally or --rebuild is set",
    )?;
    let mut session = ConnectedSession::open(&auth, key_file, &mut status).await?;
    status.phase("checking output import trust");
    client_cache::preflight_output_import(&session.builder_public_key).await?;

    let prepared = prepare_build(&installable_label, &eval_options, &mut status).await?;
    send_build_request(
        &mut session.send,
        installable,
        requested_outputs.strings,
        &prepared,
        output_mode,
        rebuild,
    )
    .await?;

    let result = run_remote_build(&mut session, output_mode, nar_fetches, &mut status).await?;
    if !result.build_success {
        status.clear_phase();
        print_summary(
            &status,
            &installable_label,
            session.server_id,
            &prepared,
            &result,
        );
        session.close().await?;
        bail!("remote build failed");
    }

    status.phase("done");
    status.clear_phase();
    print_summary(
        &status,
        &installable_label,
        session.server_id,
        &prepared,
        &result,
    );
    session.close().await
}

impl ConnectedSession {
    async fn open(
        auth: &BuildAuth,
        key_file: Option<PathBuf>,
        status: &mut ClientStatus,
    ) -> Result<Self> {
        let server_addr = auth.server_addr();
        let server_id = server_addr.id;
        let (key, key_file_lock) = load_build_key(auth, key_file).await?;
        let endpoint = Endpoint::builder(presets::N0)
            .secret_key(key)
            .bind()
            .await?;

        status.phase("connecting");
        let conn =
            tokio::time::timeout(Duration::from_secs(30), endpoint.connect(server_addr, ALPN))
                .await
                .context("connect timed out")??;
        let (mut send, mut recv) = conn.open_bi().await?;

        write_hello(&mut send, &endpoint).await?;
        write_auth(&mut send, auth).await?;
        let builder_public_key = read_auth_ok(&mut recv, status).await?;

        Ok(Self {
            endpoint,
            conn,
            send,
            recv,
            server_id,
            builder_public_key,
            _key_file_lock: key_file_lock,
        })
    }

    async fn close(mut self) -> Result<()> {
        self.send.finish()?;
        self.conn.close(0u32.into(), b"done");
        self.endpoint.close().await;
        Ok(())
    }
}

async fn resolve_requested_outputs(
    status: &mut ClientStatus,
    installable_label: &str,
    eval_options: &nix::EvalOptions,
) -> Result<RequestedOutputs> {
    status.phase("resolving outputs");
    let paths = nix::resolve_outputs(installable_label, eval_options).await?;
    let strings = paths
        .iter()
        .map(|path| path.as_str().to_string())
        .collect::<Vec<_>>();
    Ok(RequestedOutputs { paths, strings })
}

async fn local_outputs_present(
    requested_outputs: &[nix::StorePath],
    rebuild: bool,
    status: &mut ClientStatus,
) -> Result<bool> {
    status.phase("checking local outputs");
    if rebuild {
        return Ok(false);
    }
    Ok(nix::missing_paths(requested_outputs).await?.is_empty())
}

async fn prepare_build(
    installable_label: &str,
    eval_options: &nix::EvalOptions,
    status: &mut ClientStatus,
) -> Result<PreparedBuild> {
    status.phase("resolving derivation");
    let drv_path = nix::resolve_derivation(installable_label, eval_options).await?;

    status.phase("checking closure");
    let closure_paths = nix::closure(&drv_path).await?;
    let closure_path_count = closure_paths.len();
    let closure_path_strings = closure_paths
        .iter()
        .map(|path| path.as_str().to_string())
        .collect::<Vec<_>>();

    Ok(PreparedBuild {
        drv_path,
        closure_path_count,
        closure_path_strings,
    })
}

async fn send_build_request(
    send: &mut SendStream,
    installable: String,
    output_paths: Vec<String>,
    prepared: &PreparedBuild,
    output_mode: OutputMode,
    rebuild: bool,
) -> Result<()> {
    wire::write_json(
        send,
        &Message::BuildRequest(BuildRequest {
            installable,
            drv_path: prepared.drv_path.as_str().to_string(),
            output_paths,
            output_mode,
            rebuild,
        }),
    )
    .await?;
    path_chunks::write(send, &prepared.closure_path_strings, Message::BuildPaths).await
}

async fn run_remote_build(
    session: &mut ConnectedSession,
    output_mode: OutputMode,
    nar_fetches: Option<usize>,
    status: &mut ClientStatus,
) -> Result<RemoteBuildResult> {
    let missing_paths = read_queued_missing_paths(&mut session.recv, status).await?;
    let missing_path_count = missing_paths.len();

    if !missing_paths.is_empty() {
        read_upload_ready(&mut session.recv).await?;
        upload_missing_paths(&session.conn, &missing_paths, status).await?;
    }

    let finished = read_build_messages(&mut session.recv, output_mode, status).await?;
    if !finished.success {
        return Ok(RemoteBuildResult {
            missing_path_count,
            build_success: false,
            output_paths: finished.output_paths,
            received_bytes: 0,
        });
    }

    let output_closure = wait_for_output_closure(&mut session.recv, status).await?;
    let missing_outputs = locally_missing_paths(&output_closure, status).await?;
    path_chunks::write(&mut session.send, &missing_outputs, Message::OutputRequest).await?;
    let received_bytes = client_cache::import_output_cache(
        &session.conn,
        &mut session.send,
        &mut session.recv,
        status,
        &session.builder_public_key,
        &output_closure,
        nar_fetches,
    )
    .await?;

    Ok(RemoteBuildResult {
        missing_path_count,
        build_success: true,
        output_paths: finished.output_paths,
        received_bytes,
    })
}

fn print_summary(
    status: &ClientStatus,
    installable: &str,
    server_id: EndpointId,
    prepared: &PreparedBuild,
    result: &RemoteBuildResult,
) {
    summary::print_build(
        status,
        &BuildSummary {
            server_id,
            installable,
            drv_path: prepared.drv_path.as_str(),
            closure_path_count: prepared.closure_path_count,
            missing_path_count: result.missing_path_count,
            build_success: result.build_success,
            output_paths: &result.output_paths,
            received_bytes: result.received_bytes,
        },
    );
}

async fn write_hello(send: &mut SendStream, endpoint: &Endpoint) -> Result<()> {
    wire::write_json(
        send,
        &Message::Hello(Hello {
            version: VERSION,
            node_id: endpoint.id().to_string(),
        }),
    )
    .await
}

async fn write_auth(send: &mut SendStream, auth: &BuildAuth) -> Result<()> {
    match auth {
        BuildAuth::TrustedClient { .. } => {
            wire::write_json(send, &Message::AuthTrustedClient).await
        }
        BuildAuth::Ticket(ticket) => {
            wire::write_json(
                send,
                &Message::AuthTicket(AuthTicket {
                    secret: ticket.secret(),
                }),
            )
            .await
        }
    }
}

async fn read_auth_ok(recv: &mut RecvStream, status: &mut ClientStatus) -> Result<String> {
    let auth_ok = match wire::read_json::<Message>(recv).await? {
        Message::AuthOk(auth_ok) => auth_ok,
        Message::Error(err) => bail!("{}", err.message),
        message => bail!("unexpected server message: {message:?}"),
    };
    match &auth_ok.client_name {
        Some(name) => status.phase(format!("authorized as {name}")),
        None => status.phase("authorized"),
    }
    Ok(auth_ok.builder_public_key)
}

async fn load_build_key(
    auth: &BuildAuth,
    key_file: Option<PathBuf>,
) -> Result<(SecretKey, Option<keys::KeyFileLock>)> {
    match key_file {
        Some(path) => load_locked_key(path).await,
        None => match auth {
            BuildAuth::TrustedClient { .. } => {
                load_locked_key(keys::default_client_key_path()?).await
            }
            BuildAuth::Ticket(_) => Ok((SecretKey::generate(), None)),
        },
    }
}

async fn load_locked_key(path: PathBuf) -> Result<(SecretKey, Option<keys::KeyFileLock>)> {
    let lock = keys::lock_key_file(&path).await?;
    let key = keys::load_or_create(&path)?;
    Ok((key, Some(lock)))
}

async fn read_queued_missing_paths(
    recv: &mut RecvStream,
    status: &mut ClientStatus,
) -> Result<Vec<String>> {
    match wire::read_json::<Message>(recv).await? {
        Message::BuildQueued => status.phase("queued"),
        Message::Error(err) => bail!("{}", err.message),
        message => bail!("unexpected server message: {message:?}"),
    }

    path_chunks::read_with_timeout(
        recv,
        PathListKind::MissingPaths,
        SERVER_PATH_LIST_TIMEOUT,
        SERVER_PATH_LIST_LIMITS,
        "unexpected server message",
    )
    .await
}

async fn read_upload_ready(recv: &mut RecvStream) -> Result<()> {
    match wire::read_json::<Message>(recv).await? {
        Message::InputUploadReady => Ok(()),
        Message::Error(err) => bail!("{}", err.message),
        message => bail!("unexpected server message: {message:?}"),
    }
}

async fn read_build_messages(
    recv: &mut RecvStream,
    output_mode: OutputMode,
    status: &mut ClientStatus,
) -> Result<BuildFinished> {
    status.phase(match output_mode {
        OutputMode::Nom => "building via nom",
        OutputMode::Plain => "building",
    });
    if matches!(output_mode, OutputMode::Nom) {
        status.clear_phase();
    }

    let mut logs = LogRenderer::new(output_mode)?;
    loop {
        match wire::read_json::<Message>(recv).await? {
            Message::BuildStarted => {}
            Message::NixLog(log) => print_log_line(&mut logs, &log.line, status).await,
            Message::BuildFinished(finished) => return finish_logs(logs, finished, status).await,
            Message::Error(err) => return finish_after_error(logs, status, &err.message).await,
            message => bail!("unexpected server message: {message:?}"),
        }
    }
}

async fn print_log_line(logs: &mut LogRenderer, line: &str, status: &ClientStatus) {
    if let Err(err) = logs.print(line, status).await {
        eprintln!("nom failed; continuing without log rendering: {err:#}");
        *logs = LogRenderer::Disabled;
    }
}

async fn finish_logs(
    mut logs: LogRenderer,
    finished: BuildFinished,
    status: &mut ClientStatus,
) -> Result<BuildFinished> {
    let build_success = finished.success;
    if let Err(err) = logs.finish().await
        && build_success
    {
        eprintln!("nom cleanup failed: {err:#}");
    }
    status.clear_phase();
    Ok(finished)
}

async fn finish_after_error(
    mut logs: LogRenderer,
    status: &mut ClientStatus,
    message: &str,
) -> Result<BuildFinished> {
    if let Err(log_err) = logs.finish().await {
        eprintln!("nom cleanup failed after server error: {log_err:#}");
    }
    status.clear_phase();
    bail!("{message}")
}

async fn wait_for_output_closure(
    recv: &mut RecvStream,
    status: &mut ClientStatus,
) -> Result<Vec<String>> {
    status.phase("receiving output closure");
    path_chunks::read_with_timeout(
        recv,
        PathListKind::OutputClosure,
        SERVER_PATH_LIST_TIMEOUT,
        SERVER_PATH_LIST_LIMITS,
        "unexpected server message",
    )
    .await
}

async fn locally_missing_paths(paths: &[String], status: &mut ClientStatus) -> Result<Vec<String>> {
    status.phase("checking local outputs");
    let paths = paths
        .iter()
        .cloned()
        .map(nix::StorePath::new)
        .collect::<Result<Vec<_>>>()?;
    let missing = nix::missing_paths(&paths).await?;
    Ok(missing
        .iter()
        .map(|path| path.as_str().to_string())
        .collect())
}

async fn upload_missing_paths(
    conn: &Connection,
    paths: &[String],
    status: &mut ClientStatus,
) -> Result<()> {
    status.phase("preparing input upload");
    let paths = paths
        .iter()
        .cloned()
        .map(nix::StorePath::new)
        .collect::<Result<Vec<_>>>()?;
    let stream = conn.open_uni().await.context("open input upload stream")?;
    let message = format!("send {} {}", paths.len(), summary::path_word(paths.len()));
    let progress = status.transfer(message);
    let mut stream = ProgressWriter::new(stream, progress.clone());

    let result = nix::export_paths(&paths, &mut stream).await;
    let mut stream = stream.into_inner();
    progress.finish_and_clear();
    result?;

    stream.finish()?;
    Ok(())
}
