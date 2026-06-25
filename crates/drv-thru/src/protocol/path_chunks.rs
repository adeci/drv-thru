use std::time::Duration;

use anyhow::{Context, Result, bail};
use iroh::endpoint::{RecvStream, SendStream};

use crate::protocol::{Message, PathListChunk, wire};

const PATH_CHUNK_SIZE: usize = 512;

#[derive(Clone, Copy)]
pub(crate) struct ReadLimits {
    pub(crate) chunks: usize,
    pub(crate) paths: usize,
    pub(crate) bytes: usize,
}

#[derive(Clone, Copy)]
pub(crate) enum PathListKind {
    BuildPaths,
    MissingPaths,
    OutputClosure,
    OutputRequest,
}

struct ReadState {
    chunks: usize,
    path_bytes: usize,
}

pub(crate) async fn write(
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

pub(crate) async fn read_with_timeout(
    recv: &mut RecvStream,
    kind: PathListKind,
    timeout: Duration,
    limits: ReadLimits,
    unexpected_context: &str,
) -> Result<Vec<String>> {
    read_loop(recv, kind, Some(timeout), Some(limits), unexpected_context).await
}

async fn read_loop(
    recv: &mut RecvStream,
    kind: PathListKind,
    timeout: Option<Duration>,
    limits: Option<ReadLimits>,
    unexpected_context: &str,
) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    let mut state = ReadState {
        chunks: 0,
        path_bytes: 0,
    };

    loop {
        let chunk = read_chunk(recv, kind, timeout, unexpected_context).await?;
        if let Some(limits) = limits {
            check_limits(&paths, &chunk, &mut state, limits)?;
        }

        paths.extend(chunk.paths);
        if chunk.done {
            return Ok(paths);
        }
    }
}

async fn read_chunk(
    recv: &mut RecvStream,
    kind: PathListKind,
    timeout: Option<Duration>,
    unexpected_context: &str,
) -> Result<PathListChunk> {
    let message = read_message(recv, timeout).await?;
    match (kind, message) {
        (PathListKind::BuildPaths, Message::BuildPaths(chunk))
        | (PathListKind::MissingPaths, Message::MissingPaths(chunk))
        | (PathListKind::OutputClosure, Message::OutputClosure(chunk))
        | (PathListKind::OutputRequest, Message::OutputRequest(chunk)) => Ok(chunk),
        (_, Message::Error(err)) => bail!("{}", err.message),
        (_, message) => bail!("{unexpected_context}: {message:?}"),
    }
}

async fn read_message(recv: &mut RecvStream, timeout: Option<Duration>) -> Result<Message> {
    match timeout {
        Some(timeout) => tokio::time::timeout(timeout, wire::read_json(recv))
            .await
            .context("read timed out")?,
        None => wire::read_json(recv).await,
    }
}

fn check_limits(
    paths: &[String],
    chunk: &PathListChunk,
    state: &mut ReadState,
    limits: ReadLimits,
) -> Result<()> {
    state.chunks += 1;
    if state.chunks > limits.chunks {
        bail!("path list exceeded {} chunks", limits.chunks);
    }
    if paths.len().saturating_add(chunk.paths.len()) > limits.paths {
        bail!("path list exceeded {} paths", limits.paths);
    }
    state.path_bytes = state
        .path_bytes
        .checked_add(chunk.paths.iter().map(String::len).sum::<usize>())
        .context("path list byte count overflow")?;
    if state.path_bytes > limits.bytes {
        bail!("path list exceeded {} bytes", limits.bytes);
    }

    Ok(())
}
