use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::Serialize;

pub(crate) fn write_atomic<T>(path: &Path, value: &T, encode_context: &'static str) -> Result<()>
where
    T: Serialize,
{
    write_atomic_inner(path, value, encode_context, None)
}

pub(crate) fn write_atomic_with_mode<T>(
    path: &Path,
    value: &T,
    encode_context: &'static str,
    mode: u32,
) -> Result<()>
where
    T: Serialize,
{
    write_atomic_inner(path, value, encode_context, Some(mode))
}

fn write_atomic_inner<T>(
    path: &Path,
    value: &T,
    encode_context: &'static str,
    mode: Option<u32>,
) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let mut body = serde_json::to_vec_pretty(value).context(encode_context)?;
    body.push(b'\n');

    let tmp_path = temp_path_for(path)?;
    let write_result = write_temp_file(&tmp_path, &body, mode);
    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    fs::rename(&tmp_path, path)
        .with_context(|| format!("rename {} to {}", tmp_path.display(), path.display()))
}

fn write_temp_file(path: &Path, body: &[u8], mode: Option<u32>) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }

    let mut file = options
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    set_existing_temp_permissions(&file, mode)?;
    file.write_all(body)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))
}

fn set_existing_temp_permissions(file: &fs::File, mode: Option<u32>) -> Result<()> {
    #[cfg(unix)]
    if let Some(mode) = mode {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(mode))
            .context("set temp file permissions")?;
    }
    #[cfg(not(unix))]
    let _ = (file, mode);

    Ok(())
}

fn temp_path_for(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("path has no UTF-8 file name: {}", path.display()))?;
    Ok(path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id())))
}
