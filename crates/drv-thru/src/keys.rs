use std::{
    fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use iroh::SecretKey;

pub struct KeyFileLock {
    path: PathBuf,
}

impl Drop for KeyFileLock {
    fn drop(&mut self) {
        let _ = remove_key_file_lock(&self.path);
    }
}

pub fn load_or_create(path: impl AsRef<Path>) -> Result<SecretKey> {
    let path = path.as_ref();
    if path.exists() {
        return read_key(path);
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let key = SecretKey::generate();
    match write_new_key(path, &key) {
        Ok(()) => Ok(key),
        Err(err) if err.kind() == ErrorKind::AlreadyExists => read_key(path),
        Err(err) => Err(err).with_context(|| format!("write {}", path.display())),
    }
}

pub fn default_client_key_path() -> Result<PathBuf> {
    let home = std::env::var_os("HOME").context("HOME is not set; pass --key-file")?;
    Ok(PathBuf::from(home).join(".config/drv-thru/secret.key"))
}

pub async fn lock_key_file(path: &Path) -> Result<KeyFileLock> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let lock_path = key_file_lock_path(path)?;
    let mut printed_wait = false;
    loop {
        match create_key_file_lock(&lock_path) {
            Ok(()) => return Ok(KeyFileLock { path: lock_path }),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                remove_stale_key_file_lock(&lock_path)?;
                if !printed_wait {
                    eprintln!("client key in use; waiting: {}", path.display());
                    printed_wait = true;
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(err) => return Err(err).with_context(|| format!("lock {}", path.display())),
        }
    }
}

pub fn server_key_path(data_dir: &Path) -> PathBuf {
    data_dir.join("secret.key")
}

fn read_key(path: &Path) -> Result<SecretKey> {
    check_key_permissions(path)?;
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if bytes.len() == 32 {
        let bytes: [u8; 32] = bytes.as_slice().try_into().expect("checked length");
        return Ok(SecretKey::from_bytes(&bytes));
    }

    let text = String::from_utf8(bytes)
        .with_context(|| format!("{} is not a raw or text secret key", path.display()))?;
    SecretKey::from_str(text.trim()).with_context(|| format!("parse {}", path.display()))
}

fn write_new_key(path: &Path, key: &SecretKey) -> std::io::Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(&key.to_bytes())
}

fn key_file_lock_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .context("key file path must include a file name")?
        .to_string_lossy();
    Ok(path.with_file_name(format!(".{file_name}.lock")))
}

fn create_key_file_lock(path: &Path) -> std::io::Result<()> {
    // Unix symlinks let us create the lock and store the owner PID atomically.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(std::process::id().to_string(), path)
    }

    #[cfg(not(unix))]
    {
        fs::create_dir(path)
    }
}

fn remove_stale_key_file_lock(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let pid_text = match fs::read_link(path) {
            Ok(pid) => pid.to_string_lossy().into_owned(),
            Err(_) => fs::read_to_string(path.join("pid")).unwrap_or_default(),
        };
        let Ok(pid) = pid_text.trim().parse::<u32>() else {
            return remove_key_file_lock(path);
        };
        if Path::new("/proc").join(pid.to_string()).exists() {
            return Ok(());
        }
        remove_key_file_lock(path)?;
    }

    Ok(())
}

fn remove_key_file_lock(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::IsADirectory => {
            fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove {}", path.display())),
    }
}

fn check_key_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mode = fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            bail!("{} permissions are too open; run chmod 600", path.display());
        }
    }

    Ok(())
}
