use std::{
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
};

use crate::{
    cache,
    client_status::{ClientStatus, ProgressReader, TransferProgress},
    import_helper, nix,
    proto::{CacheFileRequest, CacheFileResponse, Message, OutputCacheReady},
    wire,
};

const CACHE_FILE_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(30);
const CACHE_FILE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30 * 60);

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
) -> Result<u64> {
    status.phase("waiting for signed output cache");
    match wire::read_json::<Message>(recv).await? {
        Message::OutputCacheReady(cache) => {
            let import_result =
                import_outputs_from_cache(conn.clone(), &cache, status, builder_public_key).await;
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
) -> Result<u64> {
    let copy_paths = cache
        .copy_paths
        .iter()
        .cloned()
        .map(nix::StorePath::new)
        .collect::<Result<Vec<_>>>()?;
    status.phase("checking output import trust");
    let import_method = output_import_method(builder_public_key).await?;
    let message = format!("recv {} {}", copy_paths.len(), path_word(copy_paths.len()));
    let progress = status.transfer(message);
    let bridge = CacheBridge::start(conn, progress.clone()).await?;

    let copy_result = match import_method {
        OutputImportMethod::Direct(import_trust) => {
            nix::copy_from_signed_binary_cache(
                bridge.url(),
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
                    cache_url: bridge.url().to_string(),
                    paths: copy_paths
                        .iter()
                        .map(|path| path.as_str().to_string())
                        .collect(),
                },
            )
            .await
        }
    };
    let bridge_result = bridge.shutdown().await;
    let bytes = progress.bytes();
    progress.finish_and_clear();

    match (copy_result, bridge_result) {
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
    direct_import_error: &str,
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
        "This client is not set up to import outputs from this ticket builder.\n\n\
         This user is not a trusted Nix user, and this builder key is not trusted by local Nix config.\n\
         For one-off ticket builds, either add the user to `nix.settings.trusted-users` or enable the drv-thru import helper.\n\n\
         {helper_status}\n\n\
         Helper setup for normal multi-user Nix clients:\n\n\
           services.drv-thru.client.enable = true;\n\
           services.drv-thru.client.ticketHelper.enable = true;\n\
           users.users.<name>.extraGroups = [ \"drv-thru\" ];\n\n\
         Then rebuild, log out and back in, and retry.\n\n\
         Other option: add the builder key to `nix.settings.trusted-public-keys`.\n\n\
         Running `nix run github:adeci/drv-thru#drv-thru` only runs the CLI; it does not install the helper or change Nix trust.\n\n\
         Nix preflight detail:\n{direct_import_error}"
    )
}

fn cache_bridge_status_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        let message = cause.to_string();
        message.starts_with("cache bridge returned 404")
            || message.starts_with("cache bridge returned 502")
    })
}

struct CacheBridge {
    url: String,
    shutdown: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<Result<()>>,
}

impl CacheBridge {
    async fn start(conn: Connection, progress: TransferProgress) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("bind local cache bridge")?;
        let url = format!("http://{}", listener.local_addr()?);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(run_cache_bridge(listener, conn, progress, shutdown_rx));

        Ok(Self {
            url,
            shutdown: Some(shutdown_tx),
            handle,
        })
    }

    fn url(&self) -> &str {
        &self.url
    }

    async fn shutdown(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.handle.await.context("cache bridge task panicked")?
    }
}

async fn run_cache_bridge(
    listener: TcpListener,
    conn: Connection,
    progress: TransferProgress,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    let first_error = Arc::new(Mutex::new(None));
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept local cache HTTP connection")?;
                let conn = conn.clone();
                let progress = progress.clone();
                let first_error = first_error.clone();
                tasks.spawn(async move {
                    if let Err(err) = handle_cache_http(stream, conn, progress).await {
                        let message = err.to_string();
                        eprintln!("cache bridge request failed: {message}");
                        if let Ok(mut first_error) = first_error.lock() {
                            first_error.get_or_insert(message);
                        }
                    }
                });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result {
                    result.context("cache HTTP task panicked")?;
                }
            }
        }
    }

    while let Some(result) = tasks.join_next().await {
        result.context("cache HTTP task panicked")?;
    }
    if let Ok(mut first_error) = first_error.lock()
        && let Some(first_error) = first_error.take()
    {
        bail!("{first_error}");
    }
    Ok(())
}

async fn handle_cache_http(
    mut stream: TcpStream,
    conn: Connection,
    progress: TransferProgress,
) -> Result<()> {
    let request = match read_http_request(&mut stream).await {
        Ok(request) => request,
        Err(err) => {
            let _ = write_http_head(&mut stream, 400, 0).await;
            return Err(err);
        }
    };

    if !matches!(request.method, HttpMethod::Get | HttpMethod::Head) {
        write_http_head(&mut stream, 405, 0).await?;
        return Ok(());
    }

    let path = match cache::sanitize_http_cache_path(&request.target) {
        Ok(path) => path,
        Err(_) => {
            write_http_head(&mut stream, 400, 0).await?;
            return Ok(());
        }
    };

    let send_body = matches!(request.method, HttpMethod::Get);
    let fetched = match fetch_cache_file(&conn, &path, send_body).await {
        Ok(fetched) => fetched,
        Err(err) => {
            let _ = write_http_error(
                &mut stream,
                502,
                &format!("cache fetch failed: {path}: {err:#}\n"),
            )
            .await;
            return Err(err).with_context(|| format!("cache bridge returned 502 for {path}"));
        }
    };

    let Some(mut fetched) = fetched else {
        write_http_error(&mut stream, 404, &format!("cache file not found: {path}\n")).await?;
        bail!("cache bridge returned 404 for {path}");
    };

    write_http_head(&mut stream, 200, fetched.byte_count).await?;
    if let Some(body) = fetched.body.take() {
        let mut body = ProgressReader::new(body.take(fetched.byte_count), progress);
        let copied = tokio::io::copy(&mut body, &mut stream)
            .await
            .context("stream cache body to local Nix")?;
        if copied != fetched.byte_count {
            bail!("short cache body: {copied} of {} bytes", fetched.byte_count);
        }
    }
    Ok(())
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

fn path_word(count: usize) -> &'static str {
    if count == 1 { "path" } else { "paths" }
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

        assert!(err.contains("setup required"));
        assert!(err.contains("No drv-thru import helper socket was found"));
        assert!(err.contains("services.drv-thru.client.ticketHelper.enable = true"));
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
