use std::{
    io::Write,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};

use crate::server;

use super::data_dir::SYSTEM_DATA_DIR;

pub(super) async fn show(data_dir: Option<PathBuf>, watch: bool) -> Result<()> {
    let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(SYSTEM_DATA_DIR));
    loop {
        let snapshot = server::status::read_snapshot(&data_dir).with_context(|| {
            format!(
                "read local builder status from {}; is drv-thru serve running?",
                server::status::status_path(&data_dir).display()
            )
        })?;
        print(&snapshot)?;
        if !watch {
            return Ok(());
        }
        println!();
        std::io::stdout().flush().context("flush status output")?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn print(snapshot: &server::status::StatusSnapshot) -> Result<()> {
    let now = now_unix_secs()?;
    println!("server: {}", snapshot.server.endpoint_id);
    println!(
        "builds: active {}/{}, queued {}, recent {}",
        snapshot.server.active_count,
        snapshot.server.configured_concurrency,
        snapshot.server.queued_count,
        snapshot.recent.len()
    );

    print_queued(snapshot, now);
    print_active(snapshot, now);
    print_recent(snapshot);
    Ok(())
}

fn print_queued(snapshot: &server::status::StatusSnapshot, now: u64) {
    if snapshot.queued.is_empty() {
        return;
    }

    println!("queued:");
    for build in &snapshot.queued {
        println!(
            "  #{} {} {} {} queued {}",
            build.position,
            build.request_id,
            build.client_label,
            build.installable,
            format_duration(now.saturating_sub(build.queued_at_unix))
        );
    }
}

fn print_active(snapshot: &server::status::StatusSnapshot, now: u64) {
    if snapshot.active.is_empty() {
        return;
    }

    println!("active:");
    for build in &snapshot.active {
        println!(
            "  {} {} {} {} elapsed {}",
            build.request_id,
            build.client_label,
            build.phase,
            build.installable,
            format_duration(now.saturating_sub(build.started_at_unix))
        );
    }
}

fn print_recent(snapshot: &server::status::StatusSnapshot) {
    if snapshot.recent.is_empty() {
        return;
    }

    println!("recent:");
    for build in &snapshot.recent {
        let duration = build
            .duration_seconds
            .map_or_else(|| "n/a".to_string(), format_duration);
        let error = build
            .short_error
            .as_deref()
            .map(|error| format!(" - {}", first_line(error)))
            .unwrap_or_default();
        println!(
            "  {} {} {} {} duration {}{}",
            build.request_id,
            format_build_result(build.result),
            build.client_label,
            build.installable,
            duration,
            error
        );
    }
}

fn format_build_result(result: server::status::BuildResult) -> &'static str {
    match result {
        server::status::BuildResult::Success => "success",
        server::status::BuildResult::Failed => "failed",
        server::status::BuildResult::Error => "error",
    }
}

fn first_line(message: &str) -> &str {
    message.lines().next().unwrap_or(message)
}

fn format_duration(seconds: u64) -> String {
    if seconds < 60 {
        return format!("{seconds}s");
    }
    let minutes = seconds / 60;
    let seconds = seconds % 60;
    if minutes < 60 {
        return format!("{minutes}m{seconds:02}s");
    }
    let hours = minutes / 60;
    let minutes = minutes % 60;
    format!("{hours}h{minutes:02}m")
}

fn now_unix_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}
