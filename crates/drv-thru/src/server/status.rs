use std::{
    fs,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::state::json;

pub const STATUS_FILE: &str = "status.json";

const STATUS_VERSION: u32 = 1;
const MAX_SHORT_ERROR_CHARS: usize = 512;

#[derive(Clone)]
pub(crate) struct StatusRegistry {
    inner: Arc<StatusInner>,
}

struct StatusInner {
    path: PathBuf,
    state: Mutex<MutableStatus>,
}

struct MutableStatus {
    next_request_seq: u64,
    snapshot: StatusSnapshot,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StatusSnapshot {
    pub version: u32,
    pub server: ServerStatus,
    pub queued: Vec<QueuedBuildStatus>,
    pub active: Vec<ActiveBuildStatus>,
    pub recent: Vec<RecentBuildStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ServerStatus {
    pub endpoint_id: String,
    pub configured_concurrency: usize,
    pub active_count: usize,
    pub queued_count: usize,
    pub recent_limit: usize,
    pub started_at_unix: u64,
    pub updated_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QueuedBuildStatus {
    pub request_id: String,
    pub client_label: String,
    pub installable: String,
    pub queued_at_unix: u64,
    pub queued_for_seconds: u64,
    pub position: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ActiveBuildStatus {
    pub request_id: String,
    pub client_label: String,
    pub installable: String,
    pub phase: String,
    pub queued_at_unix: u64,
    pub started_at_unix: u64,
    pub elapsed_seconds: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecentBuildStatus {
    pub request_id: String,
    pub client_label: String,
    pub installable: String,
    pub result: BuildResult,
    pub queued_at_unix: u64,
    pub started_at_unix: Option<u64>,
    pub finished_at_unix: u64,
    pub duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildResult {
    Success,
    Failed,
    Error,
}

impl StatusRegistry {
    pub(crate) fn new(
        data_dir: &Path,
        endpoint_id: String,
        configured_concurrency: usize,
        recent_limit: usize,
    ) -> Result<Self> {
        let now = now_unix_secs()?;
        let path = status_path(data_dir);
        let registry = Self {
            inner: Arc::new(StatusInner {
                path,
                state: Mutex::new(MutableStatus {
                    next_request_seq: 0,
                    snapshot: StatusSnapshot {
                        version: STATUS_VERSION,
                        server: ServerStatus {
                            endpoint_id,
                            configured_concurrency,
                            active_count: 0,
                            queued_count: 0,
                            recent_limit,
                            started_at_unix: now,
                            updated_at_unix: now,
                        },
                        queued: Vec::new(),
                        active: Vec::new(),
                        recent: Vec::new(),
                    },
                }),
            }),
        };
        registry.persist_current()?;
        Ok(registry)
    }

    pub(crate) fn enqueue(&self, client_label: String, installable: String) -> String {
        let request_id = self.with_status_update(|state, now| {
            state.next_request_seq += 1;
            let request_id = format!("build-{}", state.next_request_seq);
            state.snapshot.queued.push(QueuedBuildStatus {
                request_id: request_id.clone(),
                client_label,
                installable,
                queued_at_unix: now,
                queued_for_seconds: 0,
                position: 0,
            });
            request_id
        });

        match request_id {
            Some(request_id) => request_id,
            None => "build-unknown".to_string(),
        }
    }

    pub(crate) fn start(&self, request_id: &str) {
        let _ = self.with_status_update(|state, now| {
            let Some(index) = state
                .snapshot
                .queued
                .iter()
                .position(|build| build.request_id == request_id)
            else {
                return;
            };
            let queued = state.snapshot.queued.remove(index);
            state.snapshot.active.push(ActiveBuildStatus {
                request_id: queued.request_id,
                client_label: queued.client_label,
                installable: queued.installable,
                phase: "starting".to_string(),
                queued_at_unix: queued.queued_at_unix,
                started_at_unix: now,
                elapsed_seconds: 0,
            });
        });
    }

    pub(crate) fn phase(&self, request_id: &str, phase: impl Into<String>) {
        let phase = phase.into();
        let _ = self.with_status_update(|state, _now| {
            if let Some(active) = state
                .snapshot
                .active
                .iter_mut()
                .find(|build| build.request_id == request_id)
            {
                active.phase = phase;
            }
        });
    }

    pub(crate) fn finish(
        &self,
        request_id: &str,
        result: BuildResult,
        short_error: Option<String>,
    ) {
        let _ = self.with_status_update(|state, now| {
            let recent = if let Some(index) = state
                .snapshot
                .active
                .iter()
                .position(|build| build.request_id == request_id)
            {
                let active = state.snapshot.active.remove(index);
                RecentBuildStatus {
                    request_id: active.request_id,
                    client_label: active.client_label,
                    installable: active.installable,
                    result,
                    queued_at_unix: active.queued_at_unix,
                    started_at_unix: Some(active.started_at_unix),
                    finished_at_unix: now,
                    duration_seconds: Some(now.saturating_sub(active.started_at_unix)),
                    short_error: truncate_error(short_error),
                }
            } else if let Some(index) = state
                .snapshot
                .queued
                .iter()
                .position(|build| build.request_id == request_id)
            {
                let queued = state.snapshot.queued.remove(index);
                RecentBuildStatus {
                    request_id: queued.request_id,
                    client_label: queued.client_label,
                    installable: queued.installable,
                    result,
                    queued_at_unix: queued.queued_at_unix,
                    started_at_unix: None,
                    finished_at_unix: now,
                    duration_seconds: None,
                    short_error: truncate_error(short_error),
                }
            } else {
                return;
            };

            state.snapshot.recent.insert(0, recent);
            state
                .snapshot
                .recent
                .truncate(state.snapshot.server.recent_limit);
        });
    }

    pub(crate) async fn heartbeat(self) {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if self.has_live_builds()
                && let Err(err) = self.persist_current()
            {
                eprintln!("status update failed: {err:#}");
            }
        }
    }

    fn has_live_builds(&self) -> bool {
        let state = self.inner.state.lock().expect("status lock poisoned");
        !state.snapshot.queued.is_empty() || !state.snapshot.active.is_empty()
    }

    fn with_status_update<T>(
        &self,
        update: impl FnOnce(&mut MutableStatus, u64) -> T,
    ) -> Option<T> {
        let result = (|| -> Result<T> {
            let now = now_unix_secs()?;
            let mut state = self.inner.state.lock().expect("status lock poisoned");
            let result = update(&mut state, now);
            refresh_snapshot(&mut state.snapshot, now);
            json::write_atomic(&self.inner.path, &state.snapshot, "encode status JSON")?;
            Ok(result)
        })();

        match result {
            Ok(result) => Some(result),
            Err(err) => {
                eprintln!("status update failed: {err:#}");
                None
            }
        }
    }

    fn persist_current(&self) -> Result<()> {
        let now = now_unix_secs()?;
        let mut state = self.inner.state.lock().expect("status lock poisoned");
        refresh_snapshot(&mut state.snapshot, now);
        json::write_atomic(&self.inner.path, &state.snapshot, "encode status JSON")
    }
}

pub fn status_path(data_dir: impl AsRef<Path>) -> PathBuf {
    data_dir.as_ref().join(STATUS_FILE)
}

pub fn read_snapshot(data_dir: impl AsRef<Path>) -> Result<StatusSnapshot> {
    let path = status_path(data_dir);
    let text = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))
}

fn refresh_snapshot(snapshot: &mut StatusSnapshot, now: u64) {
    snapshot.server.active_count = snapshot.active.len();
    snapshot.server.queued_count = snapshot.queued.len();
    snapshot.server.updated_at_unix = now;

    for (index, queued) in snapshot.queued.iter_mut().enumerate() {
        queued.position = index + 1;
        queued.queued_for_seconds = now.saturating_sub(queued.queued_at_unix);
    }

    for active in &mut snapshot.active {
        active.elapsed_seconds = now.saturating_sub(active.started_at_unix);
    }
}

fn truncate_error(error: Option<String>) -> Option<String> {
    let error = error?;
    let mut chars = error.chars();
    let truncated = chars
        .by_ref()
        .take(MAX_SHORT_ERROR_CHARS)
        .collect::<String>();
    if chars.next().is_some() {
        Some(format!("{truncated}\n[truncated]"))
    } else {
        Some(truncated)
    }
}

fn now_unix_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_queue_active_and_recent_builds() {
        let data_dir = temp_data_dir("status-lifecycle");
        let status = StatusRegistry::new(&data_dir, "server".to_string(), 1, 2).unwrap();

        let first = status.enqueue("client:a".to_string(), "nixpkgs#hello".to_string());
        let second = status.enqueue("ticket:b".to_string(), "nixpkgs#ripgrep".to_string());
        status.start(&first);
        status.phase(&first, "building");
        status.finish(&first, BuildResult::Success, None);

        let snapshot = read_snapshot(&data_dir).unwrap();
        assert_eq!(snapshot.server.configured_concurrency, 1);
        assert_eq!(snapshot.server.active_count, 0);
        assert_eq!(snapshot.server.queued_count, 1);
        assert_eq!(snapshot.queued[0].request_id, second);
        assert_eq!(snapshot.queued[0].position, 1);
        assert_eq!(snapshot.recent[0].request_id, first);
        assert_eq!(snapshot.recent[0].result, BuildResult::Success);

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn bounds_recent_builds() {
        let data_dir = temp_data_dir("status-recent-limit");
        let status = StatusRegistry::new(&data_dir, "server".to_string(), 1, 1).unwrap();

        let first = status.enqueue("client:a".to_string(), "a".to_string());
        status.start(&first);
        status.finish(&first, BuildResult::Success, None);
        let second = status.enqueue("client:a".to_string(), "b".to_string());
        status.start(&second);
        status.finish(&second, BuildResult::Failed, Some("failed".to_string()));

        let snapshot = read_snapshot(&data_dir).unwrap();
        assert_eq!(snapshot.recent.len(), 1);
        assert_eq!(snapshot.recent[0].request_id, second);
        assert_eq!(snapshot.recent[0].short_error.as_deref(), Some("failed"));

        let _ = fs::remove_dir_all(data_dir);
    }

    fn temp_data_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "drv-thru-{name}-{}-{}",
            std::process::id(),
            now_unix_secs().unwrap()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
