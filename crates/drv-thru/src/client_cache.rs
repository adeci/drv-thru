mod local_server;
mod mirror;

use std::{
    collections::BTreeSet,
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{
    client_status::{ClientStatus, TransferProgress},
    import_helper, nix,
    proto::{CacheFileRequest, CacheFileResponse, Message, OutputCacheReady},
    wire,
};

use self::local_server::LocalCacheServer;

const CACHE_FILE_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const CACHE_FILE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_NARINFO_BYTES: u64 = 1024 * 1024;

pub(crate) async fn preflight_output_import(public_key: &str) -> Result<()> {
    let _ = output_import_method(public_key).await?;
    Ok(())
}

pub(crate) async fn import_output_cache(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    status: &mut ClientStatus,
    builder_public_key: &str,
    output_closure: &[String],
    nar_fetches: Option<usize>,
) -> Result<u64> {
    status.phase("waiting for signed output cache");
    match wire::read_json::<Message>(recv).await? {
        Message::OutputCacheReady(cache) => {
            let import_result = import_outputs_from_cache(
                conn.clone(),
                &cache,
                status,
                builder_public_key,
                output_closure,
                nar_fetches,
            )
            .await;
            let done_result = wire::write_json(send, &Message::OutputCacheDone).await;
            let server_done_result = if done_result.is_ok() {
                read_server_done(recv).await
            } else {
                Ok(())
            };

            match import_result {
                Ok(bytes) => {
                    done_result?;
                    server_done_result?;
                    Ok(bytes)
                }
                Err(err) => Err(err),
            }
        }
        Message::Done => Ok(0),
        Message::Error(err) => bail!("{}", err.message),
        message => bail!("unexpected server message: {message:?}"),
    }
}

async fn read_server_done(recv: &mut RecvStream) -> Result<()> {
    match wire::read_json::<Message>(recv).await? {
        Message::Done => Ok(()),
        Message::Error(err) => bail!("{}", err.message),
        message => bail!("unexpected server message: {message:?}"),
    }
}

async fn import_outputs_from_cache(
    conn: Connection,
    cache: &OutputCacheReady,
    status: &mut ClientStatus,
    builder_public_key: &str,
    output_closure: &[String],
    nar_fetches: Option<usize>,
) -> Result<u64> {
    let copy_paths = cache
        .copy_paths
        .iter()
        .cloned()
        .map(nix::StorePath::new)
        .collect::<Result<Vec<_>>>()?;
    let closure_paths = output_closure
        .iter()
        .cloned()
        .map(nix::StorePath::new)
        .collect::<Result<Vec<_>>>()?;
    status.phase("checking output import trust");
    let import_method = output_import_method(builder_public_key).await?;
    let progress = status.transfer("mirroring signed output cache");
    let nar_fetches = mirror::parallel_nar_fetches(nar_fetches)?;
    let cache_progress = CacheProgress::new(
        progress.clone(),
        closure_paths.len(),
        copy_paths.len(),
        nar_fetches,
    );
    let mirror = mirror::build(
        conn,
        &closure_paths,
        &copy_paths,
        cache_progress,
        nar_fetches,
    )
    .await?;
    let local_cache = LocalCacheServer::start(mirror.dir().to_path_buf()).await?;

    let copy_result = match import_method {
        OutputImportMethod::Direct(import_trust) => {
            nix::copy_from_signed_binary_cache(
                local_cache.url(),
                builder_public_key,
                import_trust,
                &copy_paths,
            )
            .await
        }
        OutputImportMethod::Helper => {
            import_helper::import_paths(
                Path::new(import_helper::DEFAULT_SOCKET_PATH),
                import_helper::ImportRequest {
                    builder_public_key: builder_public_key.to_string(),
                    cache_url: local_cache.url().to_string(),
                    paths: copy_paths
                        .iter()
                        .map(|path| path.as_str().to_string())
                        .collect(),
                },
            )
            .await
        }
    };
    let server_result = local_cache.shutdown().await;
    let mirror_result = mirror.cleanup().await;
    let bytes = progress.bytes();
    progress.finish_and_clear();

    match (copy_result, server_result.and(mirror_result)) {
        (Ok(()), Ok(())) => Ok(bytes),
        (Err(err), Ok(())) => Err(err),
        (Ok(()), Err(err)) => Err(err),
        (Err(copy_err), Err(bridge_err)) if cache_bridge_status_error(&bridge_err) => {
            Err(copy_err).with_context(|| bridge_err.to_string())
        }
        (Err(copy_err), Err(_)) => Err(copy_err),
    }
}

async fn output_import_method(public_key: &str) -> Result<OutputImportMethod> {
    match nix::signed_cache_import_trust(public_key).await {
        Ok(trust) => Ok(OutputImportMethod::Direct(trust)),
        Err(err) => {
            let helper_socket = Path::new(import_helper::DEFAULT_SOCKET_PATH);
            match choose_output_import_method(
                Err(err.to_string()),
                import_helper::helper_socket_status(helper_socket),
            ) {
                Ok(method) => Ok(method),
                Err(message) => bail!("{message}"),
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum OutputImportMethod {
    Direct(nix::SignedCacheImportTrust),
    Helper,
}

fn choose_output_import_method(
    direct_import: Result<nix::SignedCacheImportTrust, String>,
    helper_socket_status: import_helper::HelperSocketStatus,
) -> Result<OutputImportMethod, String> {
    match direct_import {
        Ok(trust) => Ok(OutputImportMethod::Direct(trust)),
        Err(_) if helper_socket_status == import_helper::HelperSocketStatus::Available => {
            Ok(OutputImportMethod::Helper)
        }
        Err(err) => Err(output_import_setup_error(&err, helper_socket_status)),
    }
}

fn output_import_setup_error(
    _direct_import_error: &str,
    helper_socket_status: import_helper::HelperSocketStatus,
) -> String {
    let helper_socket = import_helper::DEFAULT_SOCKET_PATH;
    let helper_status = match helper_socket_status {
        import_helper::HelperSocketStatus::Available => {
            format!(
                "A drv-thru import helper is available at {helper_socket}, but it was not selected."
            )
        }
        import_helper::HelperSocketStatus::Missing => {
            format!("No drv-thru import helper socket was found at {helper_socket}.")
        }
        import_helper::HelperSocketStatus::NotSocket => {
            format!("The path {helper_socket} exists, but it is not a Unix socket.")
        }
        import_helper::HelperSocketStatus::Inaccessible(err) => {
            format!(
                "The drv-thru import helper socket at {helper_socket} could not be inspected: {err}"
            )
        }
    };

    format!(
        "This client cannot import outputs from this ticket builder.\n\n\
         Nix does not trust this builder key for the current user, and no usable drv-thru import helper is available.\n\
         {helper_status}\n\n\
         For one-off tickets on normal multi-user NixOS clients, install the helper:\n\n\
           services.drv-thru.client.enable = true;\n\
           services.drv-thru.client.ticketHelper.enable = true;\n\
           users.users.<name>.extraGroups = [ \"drv-thru\" ];\n\n\
         Then rebuild, log out and back in if group membership changed, and retry.\n\n\
         For a persistent trusted builder, add its signing key to:\n\n\
           services.drv-thru.client.trustedBuilders.<name>.publicKey\n\n\
         `nix run github:adeci/drv-thru#drv-thru` only runs the CLI; it does not install the helper or change Nix trust."
    )
}

fn cache_bridge_status_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string();
        message.starts_with("cache bridge returned 404")
            || message.starts_with("cache bridge returned 502")
    })
}

#[derive(Clone)]
struct CacheProgress {
    transfer: TransferProgress,
    state: Arc<Mutex<CacheProgressState>>,
}

struct CacheProgressState {
    metadata_seen: BTreeSet<String>,
    payload_seen: BTreeSet<String>,
    metadata_total: usize,
    payload_total: usize,
    nar_fetches: usize,
}

impl CacheProgress {
    fn new(
        transfer: TransferProgress,
        metadata_total: usize,
        payload_total: usize,
        nar_fetches: usize,
    ) -> Self {
        let progress = Self {
            transfer,
            state: Arc::new(Mutex::new(CacheProgressState {
                metadata_seen: BTreeSet::new(),
                payload_seen: BTreeSet::new(),
                metadata_total,
                payload_total,
                nar_fetches,
            })),
        };
        progress.refresh();
        progress
    }

    fn transfer(&self) -> TransferProgress {
        self.transfer.clone()
    }

    fn record_cache_file(&self, path: &str, send_body: bool) {
        if let Ok(mut state) = self.state.lock() {
            if path.ends_with(".narinfo") {
                state.metadata_seen.insert(path.to_string());
            } else if send_body && path.starts_with("nar/") {
                state.payload_seen.insert(path.to_string());
            }
        }
        self.refresh();
    }

    fn refresh(&self) {
        let Ok(state) = self.state.lock() else {
            return;
        };
        self.transfer.message(format!(
            "cache metadata {}, payloads {}, nar {}x",
            progress_count(state.metadata_seen.len(), state.metadata_total),
            progress_count(state.payload_seen.len(), state.payload_total),
            state.nar_fetches
        ));
    }
}

fn progress_count(done: usize, total: usize) -> String {
    if total == 0 {
        done.to_string()
    } else {
        format!("{done}/{total}")
    }
}

struct HttpRequest {
    method: HttpMethod,
    target: String,
}

#[derive(Clone, Copy)]
enum HttpMethod {
    Get,
    Head,
    Other,
}

struct FetchedCacheFile {
    byte_count: u64,
    body: Option<RecvStream>,
}

async fn fetch_cache_file(
    conn: &Connection,
    path: &str,
    send_body: bool,
) -> Result<Option<FetchedCacheFile>> {
    let (mut send, mut recv) = tokio::time::timeout(CACHE_FILE_STREAM_OPEN_TIMEOUT, conn.open_bi())
        .await
        .context("open cache file stream timed out")?
        .context("open cache file stream")?;
    wire::write_json(
        &mut send,
        &Message::CacheFileRequest(CacheFileRequest {
            path: path.to_string(),
            send_body,
        }),
    )
    .await?;
    send.finish()?;

    let message = tokio::time::timeout(
        CACHE_FILE_RESPONSE_TIMEOUT,
        wire::read_json::<Message>(&mut recv),
    )
    .await
    .context("cache file response timed out")??;
    let response = match message {
        Message::CacheFileResponse(CacheFileResponse { found, byte_count }) => {
            CacheFileResponse { found, byte_count }
        }
        Message::Error(err) => bail!("{}", err.message),
        message => bail!("unexpected cache response: {message:?}"),
    };

    if !response.found {
        return Ok(None);
    }

    Ok(Some(FetchedCacheFile {
        byte_count: response.byte_count,
        body: send_body.then_some(recv),
    }))
}

async fn read_http_request(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await.context("read HTTP request")?;
        if read == 0 {
            bail!("HTTP request closed before headers");
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            bail!("HTTP request headers too large");
        }
    }

    let request = std::str::from_utf8(&buf).context("HTTP request was not UTF-8")?;
    let first_line = request
        .lines()
        .next()
        .context("HTTP request missing line")?;
    let mut parts = first_line.split_whitespace();
    let method = match parts.next().context("HTTP request missing method")? {
        "GET" => HttpMethod::Get,
        "HEAD" => HttpMethod::Head,
        _ => HttpMethod::Other,
    };
    let target = parts
        .next()
        .context("HTTP request missing target")?
        .to_string();
    let version = parts.next().context("HTTP request missing version")?;
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        bail!("invalid HTTP request line");
    }

    Ok(HttpRequest { method, target })
}

async fn write_http_head(stream: &mut TcpStream, code: u16, content_length: u64) -> Result<()> {
    let reason = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        502 => "Bad Gateway",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {content_length}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write HTTP response")
}

async fn write_http_error(stream: &mut TcpStream, code: u16, message: &str) -> Result<()> {
    write_http_head(stream, code, message.len() as u64).await?;
    stream
        .write_all(message.as_bytes())
        .await
        .context("write HTTP error body")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_user_uses_direct_nix_copy() {
        assert_eq!(
            choose_output_import_method(
                Ok(nix::SignedCacheImportTrust::CanPassPublicKey),
                import_helper::HelperSocketStatus::Missing,
            )
            .unwrap(),
            OutputImportMethod::Direct(nix::SignedCacheImportTrust::CanPassPublicKey)
        );
    }

    #[test]
    fn globally_trusted_builder_key_uses_direct_nix_copy_without_restricted_options() {
        assert_eq!(
            choose_output_import_method(
                Ok(nix::SignedCacheImportTrust::KeyAlreadyTrusted),
                import_helper::HelperSocketStatus::Missing,
            )
            .unwrap(),
            OutputImportMethod::Direct(nix::SignedCacheImportTrust::KeyAlreadyTrusted)
        );
    }

    #[test]
    fn untrusted_user_with_helper_socket_uses_helper() {
        assert_eq!(
            choose_output_import_method(
                Err("setup required".to_string()),
                import_helper::HelperSocketStatus::Available,
            )
            .unwrap(),
            OutputImportMethod::Helper
        );
    }

    #[test]
    fn untrusted_user_without_helper_socket_gets_clear_failure() {
        let err = choose_output_import_method(
            Err("setup required".to_string()),
            import_helper::HelperSocketStatus::Missing,
        )
        .expect_err("expected setup failure");

        assert!(err.contains("This client cannot import outputs"));
        assert!(err.contains("No drv-thru import helper socket was found"));
        assert!(err.contains("services.drv-thru.client.ticketHelper.enable = true"));
        assert!(err.contains("services.drv-thru.client.trustedBuilders.<name>.publicKey"));
        assert!(err.contains("nix run github:adeci/drv-thru#drv-thru"));
    }

    #[test]
    fn untrusted_user_with_inaccessible_helper_gets_group_hint() {
        let err = choose_output_import_method(
            Err("setup required".to_string()),
            import_helper::HelperSocketStatus::Inaccessible("permission denied".to_string()),
        )
        .expect_err("expected setup failure");

        assert!(err.contains("could not be inspected: permission denied"));
        assert!(err.contains("extraGroups = [ \"drv-thru\" ]"));
        assert!(err.contains("log out and back in"));
    }
}
