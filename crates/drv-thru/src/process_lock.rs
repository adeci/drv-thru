use std::{fs, process};

struct LockOwner {
    pid: u32,
    start_time: Option<String>,
}

pub fn current_owner_text() -> String {
    let pid = process::id();
    match process_start_time(pid) {
        Some(start_time) => format!("{pid}:{start_time}"),
        None => pid.to_string(),
    }
}

pub fn owner_is_live(owner_text: &str) -> bool {
    let Some(owner) = parse_owner(owner_text) else {
        return false;
    };

    #[cfg(target_os = "linux")]
    {
        let Some(current_start_time) = process_start_time(owner.pid) else {
            return false;
        };
        owner
            .start_time
            .as_deref()
            .is_none_or(|start_time| start_time == current_start_time)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = owner;
        false
    }
}

fn parse_owner(owner_text: &str) -> Option<LockOwner> {
    let owner_text = owner_text.trim();
    let (pid, start_time) = match owner_text.split_once(':') {
        Some((pid, start_time)) => (pid, Some(start_time.to_string())),
        None => (owner_text, None),
    };
    Some(LockOwner {
        pid: pid.parse().ok()?,
        start_time,
    })
}

fn process_start_time(pid: u32) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let comm_end = stat.rfind(") ")?;
    stat[comm_end + 2..]
        .split_whitespace()
        .nth(19)
        .map(ToString::to_string)
}
