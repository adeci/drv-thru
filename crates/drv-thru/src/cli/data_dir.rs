use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

pub(super) const SYSTEM_DATA_DIR: &str = "/var/lib/drv-thru";

pub(super) fn default_data_dir() -> Result<PathBuf> {
    let system_data_dir = PathBuf::from(SYSTEM_DATA_DIR);
    if ensure_accessible(&system_data_dir).is_ok() {
        return Ok(system_data_dir);
    }

    let user_data_dir = if let Some(path) = std::env::var_os("XDG_STATE_HOME") {
        PathBuf::from(path).join("drv-thru")
    } else {
        let home = std::env::var_os("HOME").context("HOME is not set; pass --data-dir")?;
        PathBuf::from(home).join(".local/state/drv-thru")
    };
    ensure_accessible(&user_data_dir)?;
    Ok(user_data_dir)
}

pub(super) fn optional(data_dir: Option<PathBuf>) -> Result<PathBuf> {
    match data_dir {
        Some(data_dir) => Ok(data_dir),
        None => default_data_dir(),
    }
}

fn ensure_accessible(path: &Path) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("create {}", path.display()))?;

    let probe = path.join(format!(".access-check-{}", std::process::id()));
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .with_context(|| format!("write {}", probe.display()))?;
    file.write_all(b"ok")
        .with_context(|| format!("write {}", probe.display()))?;
    drop(file);
    fs::remove_file(&probe).with_context(|| format!("remove {}", probe.display()))
}
