use std::{
    io::ErrorKind,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};

use crate::nix::{self, SignedCacheImportTrust, StorePath};

pub const DEFAULT_SOCKET_PATH: &str = "/run/drv-thru/import-helper.sock";
const MAX_MESSAGE_LEN: usize = 1024 * 1024;
const MAX_IMPORT_PATHS: usize = 8192;
const MAX_ERROR_CHARS: usize = 16 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct ImportRequest {
    pub builder_public_key: String,
    pub cache_url: String,
    pub paths: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ImportResponse {
    success: bool,
    error: Option<String>,
}

struct ValidatedImportRequest {
    builder_public_key: String,
    cache_url: String,
    paths: Vec<StorePath>,
}

pub async fn serve(socket: PathBuf) -> Result<()> {
    if let Some(parent) = socket.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!("create import helper socket directory {}", parent.display())
        })?;
    }
    remove_stale_socket(&socket)?;
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("bind import helper socket {}", socket.display()))?;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o770))
        .with_context(|| format!("chmod import helper socket {}", socket.display()))?;

    loop {
        let (stream, _) = listener
            .accept()
            .await
            .context("accept import helper connection")?;
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream).await {
                eprintln!("drv-thru import-helper: {err:#}");
            }
        });
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HelperSocketStatus {
    Available,
    Missing,
    NotSocket,
    Inaccessible(String),
}

pub fn helper_socket_status(socket: &Path) -> HelperSocketStatus {
    match std::fs::metadata(socket) {
        Ok(metadata) if metadata.file_type().is_socket() => HelperSocketStatus::Available,
        Ok(_) => HelperSocketStatus::NotSocket,
        Err(err) if err.kind() == ErrorKind::NotFound => HelperSocketStatus::Missing,
        Err(err) => HelperSocketStatus::Inaccessible(err.to_string()),
    }
}

pub async fn import_paths(socket: &Path, request: ImportRequest) -> Result<()> {
    validate_request(&request)?;

    let mut stream = match UnixStream::connect(socket).await {
        Ok(stream) => stream,
        Err(err) if err.kind() == ErrorKind::PermissionDenied => {
            bail!(
                "cannot connect to drv-thru import helper at {}: permission denied\n\n\
                 Add this user to services.drv-thru.client.ticketHelper.group (default: wheel), rebuild, log out and back in, then retry.",
                socket.display()
            )
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            bail!(
                "cannot connect to drv-thru import helper at {}: socket not found\n\n\
                 Enable services.drv-thru.client.ticketHelper, rebuild, log out and back in, then retry.",
                socket.display()
            )
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("connect import helper socket {}", socket.display()));
        }
    };
    write_json(&mut stream, &request)
        .await
        .context("send import helper request")?;
    let response: ImportResponse = read_json(&mut stream)
        .await
        .context("read import helper response")?;

    if response.success {
        Ok(())
    } else {
        bail!(
            "import helper failed: {}",
            response
                .error
                .unwrap_or_else(|| "unknown error".to_string())
        );
    }
}

async fn handle_connection(mut stream: UnixStream) -> Result<()> {
    let (uid, gid) = peer_uid_gid(&stream);
    let result = async {
        let request: ImportRequest = read_json(&mut stream).await.context("read request")?;
        eprintln!(
            "drv-thru import-helper: uid={} gid={} builder={} paths={}",
            uid,
            gid,
            public_key_name(&request.builder_public_key),
            request.paths.len()
        );
        let request = validate_request(&request)?;
        nix::copy_from_signed_binary_cache(
            &request.cache_url,
            &request.builder_public_key,
            SignedCacheImportTrust::CanPassPublicKey,
            &request.paths,
        )
        .await
    }
    .await;

    let response = match result {
        Ok(()) => ImportResponse {
            success: true,
            error: None,
        },
        Err(err) => ImportResponse {
            success: false,
            error: Some(truncate_error(err.to_string())),
        },
    };
    write_json(&mut stream, &response)
        .await
        .context("write response")
}

fn validate_request(request: &ImportRequest) -> Result<ValidatedImportRequest> {
    validate_loopback_http_url(&request.cache_url)?;
    validate_nix_public_key(&request.builder_public_key)?;

    if request.paths.is_empty() {
        bail!("import request path list is empty");
    }
    if request.paths.len() > MAX_IMPORT_PATHS {
        bail!(
            "import request has too many paths: {} > {}",
            request.paths.len(),
            MAX_IMPORT_PATHS
        );
    }

    let paths = request
        .paths
        .iter()
        .cloned()
        .map(StorePath::new)
        .collect::<Result<Vec<_>>>()?;

    Ok(ValidatedImportRequest {
        builder_public_key: request.builder_public_key.clone(),
        cache_url: request.cache_url.clone(),
        paths,
    })
}

pub fn validate_loopback_http_url(url: &str) -> Result<()> {
    if url.trim() != url {
        bail!("cache URL has surrounding whitespace");
    }

    let Some(authority) = url.strip_prefix("http://") else {
        bail!("cache URL must use http://");
    };
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
    {
        bail!("cache URL must be a loopback HTTP origin only");
    }

    if let Some(port) = authority.strip_prefix("127.0.0.1:") {
        return validate_port(port);
    }
    if let Some(port) = authority.strip_prefix("[::1]:") {
        return validate_port(port);
    }

    bail!("cache URL host must be 127.0.0.1 or [::1]");
}

fn validate_port(port: &str) -> Result<()> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("cache URL must include a numeric port");
    }
    let port: u16 = port.parse().context("cache URL port is out of range")?;
    if port == 0 {
        bail!("cache URL port must be non-zero");
    }
    Ok(())
}

pub fn validate_nix_public_key(public_key: &str) -> Result<()> {
    if public_key.trim() != public_key || public_key.is_empty() {
        bail!("builder public key is empty or has surrounding whitespace");
    }
    if public_key.chars().any(char::is_whitespace) {
        bail!("builder public key contains whitespace");
    }

    let Some((name, key)) = public_key.split_once(':') else {
        bail!("builder public key must be name:key");
    };
    if name.is_empty() || !name.chars().all(valid_key_name_char) {
        bail!("builder public key name is invalid");
    }
    if key.is_empty() || !key.bytes().all(valid_base64_byte) {
        bail!("builder public key body is invalid");
    }

    Ok(())
}

fn valid_key_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

fn valid_base64_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=')
}

fn public_key_name(public_key: &str) -> &str {
    public_key
        .split_once(':')
        .map(|(name, _)| name)
        .unwrap_or("<invalid>")
}

fn remove_stale_socket(socket: &Path) -> Result<()> {
    match std::fs::symlink_metadata(socket) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(socket)
            .with_context(|| format!("remove stale socket {}", socket.display())),
        Ok(_) => bail!("{} exists and is not a Unix socket", socket.display()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("stat socket {}", socket.display())),
    }
}

fn peer_uid_gid(stream: &UnixStream) -> (u32, u32) {
    match stream.peer_cred() {
        Ok(cred) => (cred.uid(), cred.gid()),
        Err(_) => (u32::MAX, u32::MAX),
    }
}

async fn write_json<T: Serialize>(stream: &mut UnixStream, message: &T) -> Result<()> {
    let body = serde_json::to_vec(message).context("encode helper message")?;
    if body.len() > MAX_MESSAGE_LEN {
        bail!("helper message too large: {} bytes", body.len());
    }

    let len = u32::try_from(body.len()).context("helper message length overflow")?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_json<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let mut len = [0; 4];
    stream
        .read_exact(&mut len)
        .await
        .context("read helper message length")?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MESSAGE_LEN {
        bail!("helper message too large: {len} bytes");
    }

    let mut body = vec![0; len];
    stream
        .read_exact(&mut body)
        .await
        .context("read helper message body")?;
    serde_json::from_slice(&body).context("decode helper message")
}

fn truncate_error(message: String) -> String {
    let mut chars = message.chars();
    let truncated = chars.by_ref().take(MAX_ERROR_CHARS).collect::<String>();
    if chars.next().is_some() {
        format!("{truncated}\n[truncated]")
    } else {
        truncated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "drv-thru-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PATH: &str = "/nix/store/00000000000000000000000000000000-test";

    #[test]
    fn accepts_loopback_http_urls() {
        validate_loopback_http_url("http://127.0.0.1:1234").unwrap();
        validate_loopback_http_url("http://[::1]:1234").unwrap();
    }

    #[test]
    fn rejects_non_loopback_http_urls() {
        for url in [
            "https://127.0.0.1:1234",
            "http://localhost:1234",
            "http://127.0.0.2:1234",
            "http://127.0.0.1",
            "http://127.0.0.1:0",
            "http://127.0.0.1:1234/cache",
            "http://127.0.0.1:1234?x=1",
            "file:///nix/store/cache",
            " http://127.0.0.1:1234",
        ] {
            assert!(validate_loopback_http_url(url).is_err(), "accepted {url}");
        }
    }

    #[test]
    fn accepts_valid_import_request() {
        validate_request(&valid_request()).unwrap();
    }

    #[test]
    fn rejects_invalid_import_requests() {
        let mut request = valid_request();
        request.builder_public_key = String::new();
        assert!(validate_request(&request).is_err());

        let mut request = valid_request();
        request.cache_url = "http://example.com:80".to_string();
        assert!(validate_request(&request).is_err());

        let mut request = valid_request();
        request.paths.clear();
        assert!(validate_request(&request).is_err());

        let mut request = valid_request();
        request.paths = vec!["/tmp/nope".to_string()];
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn rejects_too_many_import_paths() {
        let mut request = valid_request();
        request.paths = vec![PATH.to_string(); MAX_IMPORT_PATHS + 1];
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn validates_nix_public_key_shape() {
        validate_nix_public_key(KEY).unwrap();
        for key in [
            "drv-thru-1",
            "drv thru:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "drv-thru-1:",
            "drv-thru-1:not base64!",
            " drv-thru-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        ] {
            assert!(validate_nix_public_key(key).is_err(), "accepted {key}");
        }
    }

    fn valid_request() -> ImportRequest {
        ImportRequest {
            builder_public_key: KEY.to_string(),
            cache_url: "http://127.0.0.1:1234".to_string(),
            paths: vec![PATH.to_string()],
        }
    }
}
