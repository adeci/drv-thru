use std::{
    fmt::Write as _,
    io::Write as _,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use console::Term;

use crate::server;

use super::data_dir::SYSTEM_DATA_DIR;

pub(super) async fn show(data_dir: Option<PathBuf>, watch: bool) -> Result<()> {
    let data_dir = data_dir.unwrap_or_else(|| PathBuf::from(SYSTEM_DATA_DIR));
    let term = Term::stdout();
    let live = watch && term.is_term();

    loop {
        let snapshot = server::status::read_snapshot(&data_dir).with_context(|| {
            format!(
                "read local builder status from {}; is drv-thru serve running?",
                server::status::status_path(&data_dir).display()
            )
        })?;
        let frame = render(&snapshot)?;

        if live {
            term.clear_screen().context("clear status dashboard")?;
            term.write_str(&frame).context("write status dashboard")?;
            term.flush().context("flush status dashboard")?;
        } else {
            print!("{frame}");
            if watch {
                println!();
            }
            std::io::stdout().flush().context("flush status output")?;
        }

        if !watch {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn render(snapshot: &server::status::StatusSnapshot) -> Result<String> {
    let now = now_unix_secs()?;
    let mut out = String::new();
    writeln!(&mut out, "server: {}", snapshot.server.endpoint_id).expect("write status frame");
    writeln!(
        &mut out,
        "capacity: {} active {}/{}, queued {}",
        capacity_bar(
            snapshot.server.active_count,
            snapshot.server.configured_concurrency
        ),
        snapshot.server.active_count,
        snapshot.server.configured_concurrency,
        snapshot.server.queued_count
    )
    .expect("write status frame");

    if snapshot.active.is_empty() && snapshot.queued.is_empty() {
        out.push_str("\nidle\n");
        return Ok(out);
    }

    render_active(snapshot, now, &mut out);
    render_queued(snapshot, now, &mut out);
    Ok(out)
}

fn render_queued(snapshot: &server::status::StatusSnapshot, now: u64, out: &mut String) {
    if snapshot.queued.is_empty() {
        return;
    }

    out.push_str("\nqueued\n");
    for build in &snapshot.queued {
        writeln!(
            out,
            "  {:>2}. {} {} waiting {}\n       {}",
            build.position,
            build.request_id,
            build.client_label,
            format_duration(now.saturating_sub(build.queued_at_unix)),
            build.installable
        )
        .expect("write status frame");
    }
}

fn render_active(snapshot: &server::status::StatusSnapshot, now: u64, out: &mut String) {
    if snapshot.active.is_empty() {
        return;
    }

    out.push_str("\nactive\n");
    for build in &snapshot.active {
        writeln!(
            out,
            "  {} {} {} elapsed {}\n       {}",
            build.request_id,
            build.client_label,
            build.phase,
            format_duration(now.saturating_sub(build.started_at_unix)),
            build.installable
        )
        .expect("write status frame");
    }
}

fn capacity_bar(active: usize, total: usize) -> String {
    let total = total.max(1);
    let active = active.min(total);
    format!("[{}{}]", "#".repeat(active), ".".repeat(total - active))
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

#[cfg(test)]
mod tests {
    use crate::{
        cli::status::{capacity_bar, render},
        server::status::{
            ActiveBuildStatus, BuildResult, QueuedBuildStatus, RecentBuildStatus, ServerStatus,
            StatusSnapshot,
        },
    };

    #[test]
    fn renders_live_status_without_recent_builds() {
        let snapshot = StatusSnapshot {
            version: 1,
            server: ServerStatus {
                endpoint_id: "server-id".to_string(),
                configured_concurrency: 3,
                active_count: 1,
                queued_count: 1,
                recent_limit: 20,
                started_at_unix: 100,
                updated_at_unix: 110,
            },
            queued: vec![QueuedBuildStatus {
                request_id: "build-2".to_string(),
                client_label: "ticket:friend".to_string(),
                installable: ".#demo".to_string(),
                queued_at_unix: 100,
                queued_for_seconds: 10,
                position: 1,
            }],
            active: vec![ActiveBuildStatus {
                request_id: "build-1".to_string(),
                client_label: "client:alex".to_string(),
                installable: ".#demo".to_string(),
                phase: "building".to_string(),
                queued_at_unix: 90,
                started_at_unix: 100,
                elapsed_seconds: 10,
            }],
            recent: vec![RecentBuildStatus {
                request_id: "build-0".to_string(),
                client_label: "client:alex".to_string(),
                installable: ".#old".to_string(),
                result: BuildResult::Success,
                queued_at_unix: 1,
                started_at_unix: Some(2),
                finished_at_unix: 3,
                duration_seconds: Some(1),
                short_error: None,
            }],
        };

        let output = render(&snapshot).unwrap();

        assert!(output.contains("capacity: [#..] active 1/3, queued 1"));
        assert!(output.contains("active"));
        assert!(output.contains("queued"));
        assert!(!output.contains("build-0"));
        assert!(!output.contains(".#old"));
    }

    #[test]
    fn renders_capacity_bar() {
        assert_eq!(capacity_bar(0, 3), "[...]");
        assert_eq!(capacity_bar(2, 3), "[##.]");
        assert_eq!(capacity_bar(5, 3), "[###]");
    }
}
