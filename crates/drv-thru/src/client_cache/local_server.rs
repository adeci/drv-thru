use std::{io::ErrorKind, path::PathBuf};

use anyhow::{Context, Result, bail};
use tokio::{
    fs::File,
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
};

use crate::cache;

use super::{HttpMethod, read_http_request, write_http_error, write_http_head};

pub(super) struct LocalCacheServer {
    url: String,
    shutdown: Option<oneshot::Sender<()>>,
    handle: tokio::task::JoinHandle<Result<()>>,
}

impl LocalCacheServer {
    pub(super) async fn start(cache_dir: PathBuf) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .context("bind local cache server")?;
        let url = format!("http://{}", listener.local_addr()?);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let handle = tokio::spawn(run_local_cache_server(listener, cache_dir, shutdown_rx));

        Ok(Self {
            url,
            shutdown: Some(shutdown_tx),
            handle,
        })
    }

    pub(super) fn url(&self) -> &str {
        &self.url
    }

    pub(super) async fn shutdown(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.handle
            .await
            .context("local cache server task panicked")?
    }
}

async fn run_local_cache_server(
    listener: TcpListener,
    cache_dir: PathBuf,
    mut shutdown: oneshot::Receiver<()>,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            accepted = listener.accept() => {
                let (stream, _) = accepted.context("accept local cache HTTP connection")?;
                let cache_dir = cache_dir.clone();
                tasks.spawn(async move { handle_local_cache_http(stream, cache_dir).await });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result {
                    match result.context("local cache HTTP task panicked")? {
                        Ok(()) => {}
                        Err(err) => eprintln!("local cache request failed: {err:#}"),
                    }
                }
            }
        }
    }

    while let Some(result) = tasks.join_next().await {
        match result.context("local cache HTTP task panicked")? {
            Ok(()) => {}
            Err(err) => eprintln!("local cache request failed: {err:#}"),
        }
    }
    Ok(())
}

async fn handle_local_cache_http(mut stream: TcpStream, cache_dir: PathBuf) -> Result<()> {
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
    let file_path = cache::cache_file_path(&cache_dir, &path)?;
    let metadata = match tokio::fs::metadata(&file_path).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            write_http_error(&mut stream, 404, &format!("cache file not found: {path}\n")).await?;
            return Ok(());
        }
        Err(err) => return Err(err).with_context(|| format!("stat {}", file_path.display())),
    };

    write_http_head(&mut stream, 200, metadata.len()).await?;
    if matches!(request.method, HttpMethod::Get) {
        let mut file = File::open(&file_path)
            .await
            .with_context(|| format!("open {}", file_path.display()))?;
        let copied = tokio::io::copy(&mut file, &mut stream)
            .await
            .with_context(|| format!("serve local cache file {path}"))?;
        if copied != metadata.len() {
            bail!(
                "short local cache response: {copied} of {} bytes",
                metadata.len()
            );
        }
    }
    stream.shutdown().await.context("close HTTP response")
}
