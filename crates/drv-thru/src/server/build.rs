use std::{collections::BTreeSet, time::Duration};

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};

use crate::{
    nix,
    protocol::{
        BuildFinished, BuildRequest, Message, NixLog, OutputMode,
        path_chunks::{self, PathListKind},
        wire,
    },
};

use super::{
    CLIENT_NIX_TIMEOUT, CONTROL_TIMEOUT, PATH_LIST_LIMITS, UPLOAD_TIMEOUT,
    auth::AuthorizedConnection, output_cache, status,
};

pub(super) struct BuildStatusScope<'a> {
    pub(super) registry: &'a status::StatusRegistry,
    pub(super) request_id: &'a str,
}

pub(super) struct CheckedBuildRequest {
    pub(super) installable: String,
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

pub(super) async fn read_checked_build_request(
    recv: &mut RecvStream,
    request: BuildRequest,
) -> Result<CheckedBuildRequest> {
    let closure_paths = path_chunks::read_with_timeout(
        recv,
        PathListKind::BuildPaths,
        CLIENT_NIX_TIMEOUT,
        PATH_LIST_LIMITS,
        "unexpected path list message",
    )
    .await?;
    check_build_request(request, closure_paths)
}

pub(super) async fn run_queued_build(
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

    path_chunks::write(
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

pub(super) fn store_paths_to_strings(paths: &[nix::StorePath]) -> Vec<String> {
    paths.iter().map(|path| path.as_str().to_string()).collect()
}

fn check_build_request(
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
