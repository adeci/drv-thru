use std::{
    collections::BTreeSet,
    fs as std_fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use iroh::endpoint::Connection;
use tokio::{
    fs::{self as tokio_fs, File},
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Semaphore,
    task::JoinSet,
};

use crate::{
    cache,
    client_status::{ProgressReader, TransferProgress},
    nix,
};

use super::{CacheProgress, FetchedCacheFile, MAX_NARINFO_BYTES, fetch_cache_file};

const MAX_PARALLEL_METADATA_FETCHES: usize = 64;
const DEFAULT_PARALLEL_NAR_FETCHES: usize = 8;
const MAX_AUTO_PARALLEL_NAR_FETCHES: usize = 32;
const NAR_FETCHES_ENV: &str = "DRV_THRU_NAR_FETCHES";

pub(super) struct LocalCacheMirror {
    dir: PathBuf,
}

impl LocalCacheMirror {
    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(super) async fn cleanup(self) -> Result<()> {
        match tokio_fs::remove_dir_all(&self.dir).await {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err).with_context(|| format!("remove {}", self.dir.display())),
        }
    }
}

pub(super) async fn build(
    conn: Connection,
    closure_paths: &[nix::StorePath],
    copy_paths: &[nix::StorePath],
    progress: CacheProgress,
    nar_fetches: Option<usize>,
) -> Result<LocalCacheMirror> {
    let dir = create_local_cache_dir()?;
    write_nix_cache_info(&dir).await?;

    let copy_narinfos = copy_paths
        .iter()
        .map(narinfo_path_for_store_path)
        .collect::<BTreeSet<_>>();
    mirror_cache_files(
        &conn,
        &dir,
        closure_paths,
        &copy_narinfos,
        progress,
        nar_fetches,
    )
    .await
    .with_context(|| format!("mirror cache files into {}", dir.display()))?;

    Ok(LocalCacheMirror { dir })
}

async fn mirror_cache_files(
    conn: &Connection,
    dir: &Path,
    closure_paths: &[nix::StorePath],
    copy_narinfos: &BTreeSet<String>,
    progress: CacheProgress,
    nar_fetches: Option<usize>,
) -> Result<()> {
    let metadata_permits = std::sync::Arc::new(Semaphore::new(MAX_PARALLEL_METADATA_FETCHES));
    let payload_permits = std::sync::Arc::new(Semaphore::new(parallel_nar_fetches(nar_fetches)?));
    let mut metadata_tasks = JoinSet::new();
    let mut payload_tasks = JoinSet::new();

    for store_path in closure_paths {
        let metadata_permits = metadata_permits.clone();
        let conn = conn.clone();
        let dir = dir.to_path_buf();
        let progress = progress.clone();
        let narinfo_path = narinfo_path_for_store_path(store_path);
        let copy_path = copy_narinfos.contains(&narinfo_path);
        metadata_tasks.spawn(async move {
            let _permit = metadata_permits
                .acquire_owned()
                .await
                .context("acquire metadata mirror permit")?;
            mirror_narinfo(&conn, &dir, narinfo_path, copy_path, progress).await
        });
    }

    while let Some(result) = metadata_tasks.join_next().await {
        let Some(nar_path) = result.context("metadata mirror task panicked")?? else {
            continue;
        };
        let payload_permits = payload_permits.clone();
        let conn = conn.clone();
        let dir = dir.to_path_buf();
        let progress = progress.clone();
        payload_tasks.spawn(async move {
            let _permit = payload_permits
                .acquire_owned()
                .await
                .context("acquire payload mirror permit")?;
            mirror_nar(&conn, &dir, nar_path, progress).await
        });
    }

    while let Some(result) = payload_tasks.join_next().await {
        result.context("payload mirror task panicked")??;
    }
    Ok(())
}

async fn mirror_narinfo(
    conn: &Connection,
    dir: &Path,
    narinfo_path: String,
    copy_path: bool,
    progress: CacheProgress,
) -> Result<Option<String>> {
    let Some(mut fetched) = fetch_cache_file(conn, &narinfo_path, true).await? else {
        bail!("cache metadata not found: {narinfo_path}");
    };
    let bytes = read_fetched_body(&mut fetched, progress.transfer(), &narinfo_path).await?;
    write_cache_bytes(dir, &narinfo_path, &bytes).await?;
    progress.record_cache_file(&narinfo_path, true);

    if copy_path {
        cache::narinfo_nar_path(&bytes)
    } else {
        Ok(None)
    }
}

async fn mirror_nar(
    conn: &Connection,
    dir: &Path,
    nar_path: String,
    progress: CacheProgress,
) -> Result<()> {
    let Some(mut fetched) = fetch_cache_file(conn, &nar_path, true).await? else {
        bail!("cache payload not found: {nar_path}");
    };
    let file_path = cache::cache_file_path(dir, &nar_path)?;
    write_fetched_file(&mut fetched, &file_path, progress.transfer(), &nar_path).await?;
    progress.record_cache_file(&nar_path, true);
    Ok(())
}

async fn read_fetched_body(
    fetched: &mut FetchedCacheFile,
    progress: TransferProgress,
    path: &str,
) -> Result<Vec<u8>> {
    if fetched.byte_count > MAX_NARINFO_BYTES {
        bail!(
            "cache metadata too large: {} bytes for {path}",
            fetched.byte_count
        );
    }
    let Some(body) = fetched.body.take() else {
        bail!("cache response had no body: {path}");
    };
    let capacity = usize::try_from(fetched.byte_count).unwrap_or(0);
    let mut body = ProgressReader::new(body.take(fetched.byte_count), progress);
    let mut bytes = Vec::with_capacity(capacity);
    body.read_to_end(&mut bytes)
        .await
        .with_context(|| format!("read cache body {path}"))?;
    if bytes.len() as u64 != fetched.byte_count {
        bail!(
            "short cache body: {} of {} bytes",
            bytes.len(),
            fetched.byte_count
        );
    }
    Ok(bytes)
}

async fn write_fetched_file(
    fetched: &mut FetchedCacheFile,
    file_path: &Path,
    progress: crate::client_status::TransferProgress,
    path: &str,
) -> Result<()> {
    let Some(body) = fetched.body.take() else {
        bail!("cache response had no body: {path}");
    };
    if let Some(parent) = file_path.parent() {
        tokio_fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create {}", parent.display()))?;
    }

    let mut body = ProgressReader::new(body.take(fetched.byte_count), progress);
    let mut file = File::create(file_path)
        .await
        .with_context(|| format!("create {}", file_path.display()))?;
    let copied = tokio::io::copy(&mut body, &mut file)
        .await
        .with_context(|| format!("mirror cache file {path}"))?;
    file.flush()
        .await
        .with_context(|| format!("flush {}", file_path.display()))?;
    if copied != fetched.byte_count {
        bail!("short cache body: {copied} of {} bytes", fetched.byte_count);
    }
    Ok(())
}

async fn write_cache_bytes(dir: &Path, path: &str, bytes: &[u8]) -> Result<()> {
    let file_path = cache::cache_file_path(dir, path)?;
    if let Some(parent) = file_path.parent() {
        tokio_fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create {}", parent.display()))?;
    }
    tokio_fs::write(&file_path, bytes)
        .await
        .with_context(|| format!("write {}", file_path.display()))
}

async fn write_nix_cache_info(dir: &Path) -> Result<()> {
    write_cache_bytes(dir, "nix-cache-info", b"StoreDir: /nix/store\n").await
}

fn parallel_nar_fetches(configured: Option<usize>) -> Result<usize> {
    if let Some(configured) = configured {
        return Ok(configured);
    }

    if let Ok(value) = std::env::var(NAR_FETCHES_ENV) {
        let parsed = value
            .parse::<usize>()
            .with_context(|| format!("parse {NAR_FETCHES_ENV}={value}"))?;
        if parsed == 0 {
            bail!("{NAR_FETCHES_ENV} must be at least 1");
        }
        return Ok(parsed);
    }

    Ok(auto_parallel_nar_fetches(
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(DEFAULT_PARALLEL_NAR_FETCHES),
    ))
}

fn auto_parallel_nar_fetches(available: usize) -> usize {
    available.clamp(DEFAULT_PARALLEL_NAR_FETCHES, MAX_AUTO_PARALLEL_NAR_FETCHES)
}

fn create_local_cache_dir() -> Result<PathBuf> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("drv-thru-cache-{}-{nanos}", std::process::id()));
    std_fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    Ok(dir)
}

fn narinfo_path_for_store_path(path: &nix::StorePath) -> String {
    format!("{}.narinfo", store_path_hash(path))
}

fn store_path_hash(path: &nix::StorePath) -> &str {
    let rest = path
        .as_str()
        .strip_prefix("/nix/store/")
        .expect("StorePath already validated");
    rest.split_once('-').expect("StorePath already validated").0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_parallel_nar_fetches_clamps_to_sane_bounds() {
        assert_eq!(auto_parallel_nar_fetches(1), DEFAULT_PARALLEL_NAR_FETCHES);
        assert_eq!(auto_parallel_nar_fetches(16), 16);
        assert_eq!(
            auto_parallel_nar_fetches(128),
            MAX_AUTO_PARALLEL_NAR_FETCHES
        );
    }

    #[test]
    fn maps_store_path_to_narinfo_path() {
        let path =
            nix::StorePath::new("/nix/store/00000000000000000000000000000000-hello").unwrap();

        assert_eq!(
            narinfo_path_for_store_path(&path),
            "00000000000000000000000000000000.narinfo"
        );
    }
}
