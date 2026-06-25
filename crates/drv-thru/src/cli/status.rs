use std::{
    io::{IsTerminal, Write},
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
        if watch && std::io::stdout().is_terminal() {
            print!("\x1b[2J\x1b[H");
        }
        print(&snapshot)?;
        if !watch {
            return Ok(());
        }
        if !std::io::stdout().is_terminal() {
            println!();
        }
        std::io::stdout().flush().context("flush status output")?;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn print(snapshot: &server::status::StatusSnapshot) -> Result<()> {
    let now = now_unix_secs()?;
    println!("server: {}", snapshot.server.endpoint_id);
    println!(
        "builds: active {}/{}, queued {}",
        snapshot.server.active_count,
        snapshot.server.configured_concurrency,
        snapshot.server.queued_count
    );

    print_active(snapshot, now);
    print_queued(snapshot, now);
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
