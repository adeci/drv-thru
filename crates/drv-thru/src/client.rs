use std::{path::PathBuf, process::Stdio, time::Duration};

use anyhow::{Context, Result, bail};
use indicatif::HumanBytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayUrl, SecretKey,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, ChildStdin, Command},
};

const PATH_CHUNK_SIZE: usize = 512;

use crate::{
    client_cache,
    client_status::{ClientStatus, ProgressWriter},
    keys, nix,
    proto::{
        ALPN, AuthTicket, BuildFinished, BuildRequest, Hello, Message, OutputMode, PathListChunk,
        VERSION,
    },
    ticket::BuildTicket,
    wire,
};

pub enum BuildAuth {
    TrustedClient {
        server_id: EndpointId,
        relay_url: Option<RelayUrl>,
    },
    Ticket(BuildTicket),
}

impl BuildAuth {
    fn server_addr(&self) -> EndpointAddr {
        match self {
            BuildAuth::TrustedClient {
                server_id,
                relay_url,
            } => match relay_url {
                Some(relay_url) => EndpointAddr::new(*server_id).with_relay_url(relay_url.clone()),
                None => EndpointAddr::new(*server_id),
            },
            BuildAuth::Ticket(ticket) => ticket.addr().clone(),
        }
    }
}

pub async fn build(
    installable: String,
    auth: BuildAuth,
    key_file: Option<PathBuf>,
    output_mode: OutputMode,
) -> Result<()> {
    let mut status = ClientStatus::new();
    let installable_label = installable.clone();
    let server_addr = auth.server_addr();
    let server_id = server_addr.id;

    let (key, _key_file_lock) = load_build_key(&auth, key_file).await?;
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(key)
        .bind()
        .await?;

    status.phase("connecting");
    let conn = tokio::time::timeout(Duration::from_secs(30), endpoint.connect(server_addr, ALPN))
        .await
        .context("connect timed out")??;
    let (mut send, mut recv) = conn.open_bi().await?;

    wire::write_json(
        &mut send,
        &Message::Hello(Hello {
            version: VERSION,
            node_id: endpoint.id().to_string(),
        }),
    )
    .await?;
    match &auth {
        BuildAuth::TrustedClient { .. } => {
            wire::write_json(&mut send, &Message::AuthTrustedClient).await?;
        }
        BuildAuth::Ticket(ticket) => {
            wire::write_json(
                &mut send,
                &Message::AuthTicket(AuthTicket {
                    secret: ticket.secret(),
                }),
            )
            .await?;
        }
    }

    let auth_ok = match wire::read_json::<Message>(&mut recv).await? {
        Message::AuthOk(auth_ok) => auth_ok,
        Message::Error(err) => bail!("{}", err.message),
        message => bail!("unexpected server message: {message:?}"),
    };
    match auth_ok.client_name {
        Some(name) => status.phase(format!("authorized as {name}")),
        None => status.phase("authorized"),
    }
    let builder_public_key = auth_ok.builder_public_key;
    status.phase("checking output import trust");
    client_cache::preflight_output_import(&builder_public_key).await?;

    status.phase("resolving derivation");
    let drv_path = nix::resolve_derivation(&installable_label).await?;
    let requested_outputs = nix::resolve_outputs(&installable_label).await?;
    let requested_output_strings = requested_outputs
        .iter()
        .map(|path| path.as_str().to_string())
        .collect::<Vec<_>>();

    status.phase("checking closure");
    let closure_paths = nix::closure(&drv_path).await?;
    let closure_path_count = closure_paths.len();
    let closure_path_strings = closure_paths
        .iter()
        .map(|path| path.as_str().to_string())
        .collect::<Vec<_>>();

    wire::write_json(
        &mut send,
        &Message::BuildRequest(BuildRequest {
            installable,
            drv_path: drv_path.as_str().to_string(),
            output_paths: requested_output_strings,
            output_mode,
        }),
    )
    .await?;
    write_path_chunks(&mut send, &closure_path_strings, Message::BuildPaths).await?;

    let missing_paths = read_queued_missing_paths(&mut recv, &mut status).await?;
    let missing_path_count = missing_paths.len();

    if !missing_paths.is_empty() {
        match wire::read_json::<Message>(&mut recv).await? {
            Message::InputUploadReady => {
                upload_missing_paths(&conn, &missing_paths, &mut status).await?
            }
            Message::Error(err) => bail!("{}", err.message),
            message => bail!("unexpected server message: {message:?}"),
        }
    }

    let finished = read_build_messages(&mut recv, output_mode, &mut status).await?;
    let build_success = finished.success;
    let output_paths = finished.output_paths;

    if !build_success {
        status.clear_phase();
        print_build_summary(
            &status,
            BuildSummary {
                server_id,
                installable: &installable_label,
                drv_path: drv_path.as_str(),
                closure_path_count,
                missing_path_count,
                build_success,
                output_paths: &output_paths,
                received_bytes: 0,
            },
        );
        send.finish()?;
        conn.close(0u32.into(), b"done");
        endpoint.close().await;
        bail!("remote build failed");
    }

    let output_closure = wait_for_output_closure(&mut recv, &mut status).await?;
    let missing_outputs = locally_missing_paths(&output_closure, &mut status).await?;
    write_path_chunks(&mut send, &missing_outputs, Message::OutputRequest).await?;

    let received_bytes = client_cache::import_output_cache(
        &conn,
        &mut send,
        &mut recv,
        &mut status,
        &builder_public_key,
        &output_closure,
    )
    .await?;

    status.phase("done");
    status.clear_phase();
    print_build_summary(
        &status,
        BuildSummary {
            server_id,
            installable: &installable_label,
            drv_path: drv_path.as_str(),
            closure_path_count,
            missing_path_count,
            build_success,
            output_paths: &output_paths,
            received_bytes,
        },
    );

    send.finish()?;
    conn.close(0u32.into(), b"done");
    endpoint.close().await;

    Ok(())
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

async fn read_path_chunks(recv: &mut RecvStream, kind: PathListKind) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    loop {
        let chunk = match wire::read_json::<Message>(recv).await? {
            Message::MissingPaths(chunk) if matches!(kind, PathListKind::MissingPaths) => chunk,
            Message::OutputClosure(chunk) if matches!(kind, PathListKind::OutputClosure) => chunk,
            Message::Error(err) => bail!("{}", err.message),
            message => bail!("unexpected server message: {message:?}"),
        };
        paths.extend(chunk.paths);
        if chunk.done {
            return Ok(paths);
        }
    }
}

enum PathListKind {
    MissingPaths,
    OutputClosure,
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

    read_path_chunks(recv, PathListKind::MissingPaths).await
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

    let mut logs = LogRenderer::new(output_mode).await?;

    loop {
        match wire::read_json::<Message>(recv).await? {
            Message::BuildStarted => {}
            Message::NixLog(log) => {
                if let Err(err) = logs.print(&log.line, status).await {
                    eprintln!("nom failed; continuing without log rendering: {err:#}");
                    logs = LogRenderer::Disabled;
                }
            }
            Message::BuildFinished(finished) => {
                if let Err(err) = logs.finish().await {
                    eprintln!("nom cleanup failed: {err:#}");
                }
                status.clear_phase();
                return Ok(finished);
            }
            Message::Error(err) => {
                if let Err(log_err) = logs.finish().await {
                    eprintln!("nom cleanup failed after server error: {log_err:#}");
                }
                status.clear_phase();
                bail!("{}", err.message);
            }
            message => bail!("unexpected server message: {message:?}"),
        }
    }
}

async fn wait_for_output_closure(
    recv: &mut RecvStream,
    status: &mut ClientStatus,
) -> Result<Vec<String>> {
    status.phase("receiving output closure");
    read_path_chunks(recv, PathListKind::OutputClosure).await
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

enum LogRenderer {
    Plain,
    Nom(NomRenderer),
    Disabled,
}

impl LogRenderer {
    async fn new(output_mode: OutputMode) -> Result<Self> {
        match output_mode {
            OutputMode::Plain => Ok(Self::Plain),
            OutputMode::Nom => Ok(Self::Nom(NomRenderer::new().await?)),
        }
    }

    async fn print(&mut self, line: &str, status: &ClientStatus) -> Result<()> {
        match self {
            Self::Plain => {
                status.suspend(|| eprintln!("{line}"));
                Ok(())
            }
            Self::Nom(nom) => nom.print(line).await,
            Self::Disabled => Ok(()),
        }
    }

    async fn finish(&mut self) -> Result<()> {
        match self {
            Self::Plain | Self::Disabled => Ok(()),
            Self::Nom(nom) => nom.finish().await,
        }
    }
}

struct NomRenderer {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl NomRenderer {
    async fn new() -> Result<Self> {
        let mut child = Command::new("nom")
            .arg("--json")
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("start `nom --json`; install nom or use `--no-nom`")?;
        let stdin = child.stdin.take().context("nom stdin not piped")?;

        Ok(Self {
            child,
            stdin: Some(stdin),
        })
    }

    async fn print(&mut self, line: &str) -> Result<()> {
        let stdin = self.stdin.as_mut().context("nom stdin is closed")?;
        stdin
            .write_all(line.as_bytes())
            .await
            .context("write log line to nom")?;
        stdin
            .write_all(b"\n")
            .await
            .context("write log newline to nom")?;
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        drop(self.stdin.take());
        let status = self.child.wait().await.context("wait for nom")?;
        if !status.success() {
            bail!("nom exited with {status}");
        }
        Ok(())
    }
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
    let message = format!("send {} {}", paths.len(), path_word(paths.len()));
    let progress = status.transfer(message);
    let mut stream = ProgressWriter::new(stream, progress.clone());

    let result = nix::export_paths(&paths, &mut stream).await;
    let mut stream = stream.into_inner();
    progress.finish_and_clear();
    result?;

    stream.finish()?;
    Ok(())
}

struct BuildSummary<'a> {
    server_id: EndpointId,
    installable: &'a str,
    drv_path: &'a str,
    closure_path_count: usize,
    missing_path_count: usize,
    build_success: bool,
    output_paths: &'a [String],
    received_bytes: u64,
}

fn print_build_summary(status: &ClientStatus, summary: BuildSummary<'_>) {
    status.suspend(|| {
        println!("drv-thru: build complete");
        println!();
        println!("drv-thru -> {}", short_endpoint_id(summary.server_id));
        println!("{:<12} {}", "installable", summary.installable);
        println!("{:<12} {}", "drv", summary.drv_path);
        println!(
            "{:<12} {} missing / {} {}",
            "inputs",
            summary.missing_path_count,
            summary.closure_path_count,
            path_word(summary.closure_path_count)
        );
        println!("{:<12} started", "queue");
        println!(
            "{:<12} {}",
            "build",
            if summary.build_success {
                "succeeded"
            } else {
                "failed"
            }
        );
        println!(
            "{:<12} {} {}",
            "outputs",
            summary.output_paths.len(),
            path_word(summary.output_paths.len())
        );
        println!(
            "{:<12} {} ({} bytes)",
            "received",
            HumanBytes(summary.received_bytes),
            summary.received_bytes
        );
        println!();
        println!("output paths:");
        for path in summary.output_paths {
            println!("{path}");
        }
    });
}

fn path_word(count: usize) -> &'static str {
    if count == 1 { "path" } else { "paths" }
}

fn short_endpoint_id(id: EndpointId) -> String {
    let id = id.to_string();
    let len = id.chars().count();
    if len <= 14 {
        return id;
    }

    let start: String = id.chars().take(8).collect();
    let end: String = id
        .chars()
        .rev()
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{start}...{end}")
}
