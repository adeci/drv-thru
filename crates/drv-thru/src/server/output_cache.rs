use super::*;

const NIX_CACHE_INFO: &[u8] = b"StoreDir: /nix/store\n";

#[derive(Clone)]
pub(super) struct OutputCache {
    dir: PathBuf,
    signing_key: Arc<keys::SigningKey>,
    fill_locks: Arc<Mutex<BTreeMap<String, Arc<Mutex<()>>>>>,
    fill_permits: Arc<Semaphore>,
}

impl OutputCache {
    pub(super) fn new(
        data_dir: &Path,
        signing_key: Arc<keys::SigningKey>,
        max_parallel_fills: usize,
    ) -> Result<Self> {
        let dir = data_dir
            .join("cache")
            .join(signing_cache_dir_name(&signing_key.public_key));
        fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        Ok(Self {
            dir,
            signing_key,
            fill_locks: Arc::new(Mutex::new(BTreeMap::new())),
            fill_permits: Arc::new(Semaphore::new(max_parallel_fills)),
        })
    }

    pub(super) fn public_key(&self) -> &str {
        &self.signing_key.public_key
    }

    async fn fill_lock(&self, store_hash: &str) -> Arc<Mutex<()>> {
        let mut locks = self.fill_locks.lock().await;
        locks
            .entry(store_hash.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

#[derive(Clone)]
struct OutputCacheAccess {
    paths_by_hash: Arc<BTreeMap<String, nix::StorePath>>,
    allowed_nar_paths: Arc<Mutex<BTreeSet<String>>>,
}

impl OutputCacheAccess {
    fn new(paths: &[nix::StorePath]) -> Self {
        Self {
            paths_by_hash: Arc::new(output_cache_allowed_paths(paths)),
            allowed_nar_paths: Arc::new(Mutex::new(BTreeSet::new())),
        }
    }
}

pub(super) async fn export_outputs(
    conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    output_paths: &[nix::StorePath],
    output_cache: &OutputCache,
) -> Result<()> {
    let closure_started = Instant::now();
    let closure = nix::output_closure(output_paths).await?;
    println!(
        "output closure: {} root path(s), {} closure path(s) in {:.1}s",
        output_paths.len(),
        closure.len(),
        closure_started.elapsed().as_secs_f64()
    );
    write_path_chunks(
        send,
        &store_paths_to_strings(&closure),
        Message::OutputClosure,
    )
    .await?;

    let requested =
        read_path_chunks_with_timeout(recv, PathListKind::OutputRequest, CLIENT_NIX_TIMEOUT)
            .await
            .and_then(|request| requested_output_paths(request, &closure))?;
    println!(
        "output request: {} missing path(s) of {} closure path(s)",
        requested.len(),
        closure.len()
    );

    if requested.is_empty() {
        println!("output cache: skipped; client already has requested closure");
        return wire::write_json(send, &Message::Done).await;
    }

    // Nix may query narinfos for references of requested paths while computing the copy closure.
    // Serve any path in the output closure, but ask Nix to copy only the paths missing locally.
    let access = OutputCacheAccess::new(&closure);

    wire::write_json(
        send,
        &Message::OutputCacheReady(OutputCacheReady {
            copy_paths: store_paths_to_strings(&requested),
            closure_path_count: closure.len(),
        }),
    )
    .await?;

    let serve_started = Instant::now();
    println!(
        "output cache: serving persistent cache files over Iroh from {}",
        output_cache.dir.display()
    );
    tokio::spawn(prewarm_output_cache(
        output_cache.clone(),
        requested.clone(),
    ));
    serve_output_cache(conn, recv, output_cache.clone(), access).await?;
    println!(
        "output cache: served in {:.1}s",
        serve_started.elapsed().as_secs_f64()
    );
    wire::write_json(send, &Message::Done).await
}

async fn serve_output_cache(
    conn: &Connection,
    recv: &mut RecvStream,
    cache: OutputCache,
    access: OutputCacheAccess,
) -> Result<()> {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            message = wire::read_json::<Message>(recv) => {
                match message? {
                    Message::OutputCacheDone => break,
                    Message::Error(err) => bail!("{}", err.message),
                    message => bail!("unexpected output cache message: {message:?}"),
                }
            }
            accepted = conn.accept_bi() => {
                let (send, recv) = accepted.context("accept cache file stream")?;
                let cache = cache.clone();
                let access = access.clone();
                tasks.spawn(async move { handle_cache_file_stream(send, recv, cache, access).await });
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(result) = result
                    && let Err(err) = result.context("cache file task panicked")?
                {
                    eprintln!("output cache request failed: {err:#}");
                }
            }
        }
    }

    while let Some(result) = tasks.join_next().await {
        if let Err(err) = result.context("cache file task panicked")? {
            eprintln!("output cache request failed: {err:#}");
        }
    }
    Ok(())
}

async fn handle_cache_file_stream(
    mut send: SendStream,
    mut recv: RecvStream,
    cache: OutputCache,
    access: OutputCacheAccess,
) -> Result<()> {
    let request = match read_message_with_timeout(&mut recv, CONTROL_TIMEOUT).await? {
        Message::CacheFileRequest(request) => request,
        message => bail!("unexpected cache file request: {message:?}"),
    };

    let path = cache::sanitize_cache_path(&request.path)?;

    if path == "nix-cache-info" {
        let file_path = ensure_nix_cache_info(&cache.dir).await?;
        stream_cache_file(&mut send, &file_path, &path, request.send_body).await?;
        send.finish()?;
        return Ok(());
    }

    if path.ends_with(".narinfo") {
        let Some(store_path) =
            map_narinfo_to_allowed_store_path(&path, access.paths_by_hash.as_ref())?
        else {
            write_cache_file_response(&mut send, false, 0).await?;
            send.finish()?;
            return Ok(());
        };

        ensure_cache_entry(&cache, store_path).await?;
        let file_path = cache::cache_file_path(&cache.dir, &path)?;
        let bytes = tokio::fs::read(&file_path)
            .await
            .with_context(|| format!("read {}", file_path.display()))?;
        if let Some(nar_path) = cache::narinfo_nar_path(&bytes)? {
            access.allowed_nar_paths.lock().await.insert(nar_path);
        }
        stream_cache_bytes(&mut send, &path, &bytes, request.send_body).await?;
        send.finish()?;
        return Ok(());
    }

    if path.starts_with("nar/") {
        if !access.allowed_nar_paths.lock().await.contains(&path) {
            write_cache_file_response(&mut send, false, 0).await?;
            send.finish()?;
            return Ok(());
        }

        let file_path = cache::cache_file_path(&cache.dir, &path)?;
        stream_cache_file(&mut send, &file_path, &path, request.send_body).await?;
        send.finish()?;
        return Ok(());
    }

    bail!("unsupported cache path: {path}");
}

async fn stream_cache_file(
    send: &mut SendStream,
    path: &Path,
    request_path: &str,
    send_body: bool,
) -> Result<()> {
    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            write_cache_file_response(send, false, 0).await?;
            return Ok(());
        }
        Err(err) => return Err(err).with_context(|| format!("open {}", path.display())),
    };

    let byte_count = file
        .metadata()
        .await
        .with_context(|| format!("stat {}", path.display()))?
        .len();
    write_cache_file_response(send, true, byte_count).await?;
    println!(
        "output cache file: {} {} byte(s){}",
        request_path,
        byte_count,
        if send_body { "" } else { " head" }
    );

    if send_body {
        let mut body = file.take(byte_count);
        let copied = tokio::io::copy(&mut body, send)
            .await
            .with_context(|| format!("stream {}", path.display()))?;
        if copied != byte_count {
            bail!("short cache file read: {copied} of {byte_count} bytes");
        }
    }

    Ok(())
}

async fn stream_cache_bytes(
    send: &mut SendStream,
    request_path: &str,
    bytes: &[u8],
    send_body: bool,
) -> Result<()> {
    let byte_count = bytes.len() as u64;
    write_cache_file_response(send, true, byte_count).await?;
    println!(
        "output cache file: {} {} byte(s){}",
        request_path,
        byte_count,
        if send_body { "" } else { " head" }
    );

    if send_body {
        send.write_all(bytes)
            .await
            .with_context(|| format!("stream {request_path}"))?;
    }

    Ok(())
}

async fn prewarm_output_cache(cache: OutputCache, paths: Vec<nix::StorePath>) {
    let started = Instant::now();
    let path_count = paths.len();
    let mut tasks = JoinSet::new();
    for path in paths {
        let cache = cache.clone();
        tasks.spawn(async move {
            ensure_cache_entry(&cache, &path)
                .await
                .with_context(|| format!("prewarm {}", path.as_str()))
        });
    }

    let mut failures = 0usize;
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                failures += 1;
                eprintln!("output cache: prewarm failed: {err:#}");
            }
            Err(err) => {
                failures += 1;
                eprintln!("output cache: prewarm task panicked: {err:#}");
            }
        }
    }

    println!(
        "output cache: prewarm finished in {:.1}s, {} path(s), {} failure(s)",
        started.elapsed().as_secs_f64(),
        path_count,
        failures
    );
}

async fn ensure_nix_cache_info(cache_dir: &Path) -> Result<PathBuf> {
    let path = cache::cache_file_path(cache_dir, "nix-cache-info")?;
    if cache_file_exists(&path).await? {
        return Ok(path);
    }

    tokio::fs::create_dir_all(cache_dir)
        .await
        .with_context(|| format!("create {}", cache_dir.display()))?;
    match tokio::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .await
    {
        Ok(mut file) => file
            .write_all(NIX_CACHE_INFO)
            .await
            .with_context(|| format!("write {}", path.display()))?,
        Err(err) if err.kind() == ErrorKind::AlreadyExists => {}
        Err(err) => return Err(err).with_context(|| format!("create {}", path.display())),
    }

    Ok(path)
}

async fn ensure_cache_entry(cache: &OutputCache, store_path: &nix::StorePath) -> Result<()> {
    let store_hash = store_path_hash(store_path);
    let narinfo_path = cache.dir.join(format!("{store_hash}.narinfo"));
    if cache_entry_ready(cache, &narinfo_path).await? {
        println!("output cache: cache hit {}", store_path.as_str());
        return Ok(());
    }

    let fill_lock = cache.fill_lock(store_hash).await;
    let _fill_lock = fill_lock.lock().await;
    if cache_entry_ready(cache, &narinfo_path).await? {
        println!("output cache: cache hit {}", store_path.as_str());
        return Ok(());
    }

    let _permit = cache
        .fill_permits
        .clone()
        .acquire_owned()
        .await
        .context("cache fill semaphore closed")?;
    remove_stale_narinfo(&narinfo_path).await?;
    tokio::fs::create_dir_all(&cache.dir)
        .await
        .with_context(|| format!("create {}", cache.dir.display()))?;
    let started = Instant::now();
    println!("output cache: cache fill start {}", store_path.as_str());
    nix::copy_to_signed_binary_cache(
        std::slice::from_ref(store_path),
        &cache.dir,
        &cache.signing_key.secret_path,
    )
    .await?;
    if !cache_entry_ready(cache, &narinfo_path).await? {
        bail!(
            "cache entry was not ready after fill: {}",
            store_path.as_str()
        );
    }
    println!(
        "output cache: cache fill done in {:.1}s {}",
        started.elapsed().as_secs_f64(),
        store_path.as_str()
    );

    Ok(())
}

async fn cache_entry_ready(cache: &OutputCache, narinfo_path: &Path) -> Result<bool> {
    let bytes = match tokio::fs::read(narinfo_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(err).with_context(|| format!("read {}", narinfo_path.display())),
    };

    if !narinfo_signed_by(&bytes, &cache.signing_key.public_key)? {
        return Ok(false);
    }

    let Some(nar_path) = cache::narinfo_nar_path(&bytes)? else {
        return Ok(false);
    };
    let nar_path = cache::cache_file_path(&cache.dir, &nar_path)?;
    cache_file_exists(&nar_path).await
}

async fn remove_stale_narinfo(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("remove stale {}", path.display())),
    }
}

async fn cache_file_exists(path: &Path) -> Result<bool> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => Ok(metadata.is_file()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("stat {}", path.display())),
    }
}

fn output_cache_allowed_paths(paths: &[nix::StorePath]) -> BTreeMap<String, nix::StorePath> {
    paths
        .iter()
        .map(|path| (store_path_hash(path).to_string(), path.clone()))
        .collect()
}

fn map_narinfo_to_allowed_store_path<'a>(
    path: &str,
    allowed: &'a BTreeMap<String, nix::StorePath>,
) -> Result<Option<&'a nix::StorePath>> {
    let Some(hash) = path.strip_suffix(".narinfo") else {
        bail!("not a narinfo path: {path}");
    };
    if path.contains('/') {
        bail!("invalid narinfo path: {path}");
    }
    Ok(allowed.get(hash))
}

fn signing_cache_dir_name(public_key: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(4 + public_key.len() * 2);
    name.push_str("key-");
    for byte in public_key.as_bytes() {
        name.push(HEX[(byte >> 4) as usize] as char);
        name.push(HEX[(byte & 0x0f) as usize] as char);
    }
    name
}

fn narinfo_signed_by(bytes: &[u8], public_key: &str) -> Result<bool> {
    let Some((name, _)) = public_key.split_once(':') else {
        bail!("invalid signing public key")
    };
    let signature_prefix = format!("Sig: {name}:");
    let text = std::str::from_utf8(bytes).context("narinfo is not UTF-8")?;
    Ok(text.lines().any(|line| line.starts_with(&signature_prefix)))
}

fn store_path_hash(path: &nix::StorePath) -> &str {
    let rest = path
        .as_str()
        .strip_prefix("/nix/store/")
        .expect("StorePath already validated");
    rest.split_once('-').expect("StorePath already validated").0
}

async fn write_cache_file_response(
    send: &mut SendStream,
    found: bool,
    byte_count: u64,
) -> Result<()> {
    wire::write_json(
        send,
        &Message::CacheFileResponse(CacheFileResponse { found, byte_count }),
    )
    .await
}

fn requested_output_paths(
    request: Vec<String>,
    allowed_paths: &[nix::StorePath],
) -> Result<Vec<nix::StorePath>> {
    let allowed = allowed_paths
        .iter()
        .map(|path| path.as_str().to_string())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    let mut requested = Vec::new();

    for path in request {
        let path = nix::StorePath::new(path)?;
        if !allowed.contains(path.as_str()) {
            bail!("requested output path was not built: {}", path.as_str());
        }
        if seen.insert(path.as_str().to_string()) {
            requested.push(path);
        }
    }

    Ok(requested)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_narinfo_hash_to_allowed_store_path() {
        let store_path =
            nix::StorePath::new("/nix/store/00000000000000000000000000000000-hello").unwrap();
        let allowed = output_cache_allowed_paths(std::slice::from_ref(&store_path));

        let mapped =
            map_narinfo_to_allowed_store_path("00000000000000000000000000000000.narinfo", &allowed)
                .unwrap()
                .unwrap();

        assert_eq!(mapped.as_str(), store_path.as_str());
    }

    #[test]
    fn signing_cache_dir_name_depends_on_full_public_key() {
        assert_ne!(
            signing_cache_dir_name("drv-thru:abc"),
            signing_cache_dir_name("drv-thru:def")
        );
        assert!(signing_cache_dir_name("drv-thru:abc").starts_with("key-"));
    }

    #[test]
    fn detects_current_signing_key_in_narinfo() {
        let narinfo = b"Sig: drv-thru:abc
";
        assert!(narinfo_signed_by(narinfo, "drv-thru:public-key").unwrap());
        assert!(!narinfo_signed_by(narinfo, "other:public-key").unwrap());
    }

    #[test]
    fn rejects_unknown_narinfo_hash() {
        let store_path =
            nix::StorePath::new("/nix/store/00000000000000000000000000000000-hello").unwrap();
        let allowed = output_cache_allowed_paths(&[store_path]);

        let mapped =
            map_narinfo_to_allowed_store_path("11111111111111111111111111111111.narinfo", &allowed)
                .unwrap();

        assert!(mapped.is_none());
    }
}
