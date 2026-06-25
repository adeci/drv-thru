use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result};
use iroh::{
    Endpoint, EndpointId,
    endpoint::{Connection, RecvStream, SendStream, presets},
};
use tokio::sync::Semaphore;

use crate::{
    access::AccessPolicy,
    config::{
        DEFAULT_MAX_CONCURRENT_BUILDS, DEFAULT_RECENT_BUILDS_LIMIT, MAX_AUTO_CACHE_FILLS,
        load_server_config,
    },
    keys,
    protocol::{ALPN, ErrorMessage, Message, path_chunks::ReadLimits, wire},
    ticket::{self, TicketStore},
};

mod auth;
mod build;
mod connection;
mod output_cache;
pub(crate) mod status;

const MAX_PATH_LIST_CHUNKS: usize = 512;
const MAX_PATH_LIST_PATHS: usize = 100_000;
const MAX_PATH_LIST_BYTES: usize = 16 * 1024 * 1024;
const PATH_LIST_LIMITS: ReadLimits = ReadLimits {
    chunks: MAX_PATH_LIST_CHUNKS,
    paths: MAX_PATH_LIST_PATHS,
    bytes: MAX_PATH_LIST_BYTES,
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const CLIENT_NIX_TIMEOUT: Duration = Duration::from_mins(10);
const UPLOAD_TIMEOUT: Duration = Duration::from_mins(30);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

pub enum ServeMode {
    DataDir {
        data_dir: PathBuf,
        trusted_clients: Vec<EndpointId>,
    },
    Config(PathBuf),
}

struct ResolvedServeMode {
    data_dir: PathBuf,
    secret_key_file: Option<PathBuf>,
    access_policy: AccessPolicy,
    max_concurrent_builds: usize,
    output_cache_max_parallel_fills: Option<usize>,
    recent_builds_limit: usize,
}

pub async fn serve(mode: ServeMode) -> Result<()> {
    let mode = resolve_serve_mode(mode)?;
    let signing_key = Arc::new(keys::load_or_create_signing_key(&mode.data_dir)?);
    let output_cache_max_parallel_fills = mode
        .output_cache_max_parallel_fills
        .unwrap_or_else(default_output_cache_max_parallel_fills);
    println!("output cache max parallel fills: {output_cache_max_parallel_fills}");
    let output_cache = Arc::new(output_cache::OutputCache::new(
        &mode.data_dir,
        signing_key,
        output_cache_max_parallel_fills,
    )?);
    let endpoint = bind_endpoint(&mode.data_dir, mode.secret_key_file).await?;

    print_endpoint_addr(&endpoint).await;
    ticket::save_server_addr(&mode.data_dir, &endpoint.addr())?;

    let status = status::StatusRegistry::new(
        &mode.data_dir,
        endpoint.id().to_string(),
        mode.max_concurrent_builds,
        mode.recent_builds_limit,
    )?;
    let status_heartbeat = tokio::spawn(status.clone().heartbeat());
    let ticket_store = TicketStore::new(&mode.data_dir);
    ticket_store.load()?;
    let build_queue = Arc::new(Semaphore::new(mode.max_concurrent_builds));

    accept_loop(
        &endpoint,
        mode.access_policy,
        ticket_store,
        build_queue,
        output_cache,
        status,
    )
    .await;

    status_heartbeat.abort();
    endpoint.close().await;
    Ok(())
}

fn resolve_serve_mode(mode: ServeMode) -> Result<ResolvedServeMode> {
    match mode {
        ServeMode::DataDir {
            data_dir,
            trusted_clients,
        } => Ok(ResolvedServeMode {
            data_dir,
            secret_key_file: None,
            access_policy: AccessPolicy::from_endpoint_ids(trusted_clients),
            max_concurrent_builds: DEFAULT_MAX_CONCURRENT_BUILDS,
            output_cache_max_parallel_fills: None,
            recent_builds_limit: DEFAULT_RECENT_BUILDS_LIMIT,
        }),
        ServeMode::Config(path) => {
            let config = load_server_config(&path)?;
            let access_policy = AccessPolicy::from_config(&config)?;
            Ok(ResolvedServeMode {
                data_dir: config.data_dir,
                secret_key_file: config.secret_key_file,
                access_policy,
                max_concurrent_builds: config.max_concurrent_builds,
                output_cache_max_parallel_fills: config.output_cache_max_parallel_fills,
                recent_builds_limit: config.recent_builds_limit,
            })
        }
    }
}

fn default_output_cache_max_parallel_fills() -> usize {
    std::thread::available_parallelism()
        .map_or(4, usize::from)
        .clamp(1, MAX_AUTO_CACHE_FILLS)
}

async fn bind_endpoint(
    data_dir: &std::path::Path,
    secret_key_file: Option<PathBuf>,
) -> Result<Endpoint> {
    let key_path = secret_key_file.unwrap_or_else(|| keys::server_key_path(data_dir));
    let key = keys::load_or_create(key_path)?;
    Endpoint::builder(presets::N0)
        .secret_key(key)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .map_err(Into::into)
}

async fn print_endpoint_addr(endpoint: &Endpoint) {
    println!("server endpoint id: {}", endpoint.id());
    endpoint.online().await;

    let addr = endpoint.addr();
    for relay_url in addr.relay_urls() {
        println!("server relay url: {relay_url}");
    }
    for direct_addr in addr.ip_addrs() {
        println!("server direct addr: {direct_addr}");
    }
}

async fn accept_loop(
    endpoint: &Endpoint,
    access_policy: AccessPolicy,
    ticket_store: TicketStore,
    build_queue: Arc<Semaphore>,
    output_cache: Arc<output_cache::OutputCache>,
    status: status::StatusRegistry,
) {
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => break,
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let access_policy = access_policy.clone();
                let ticket_store = ticket_store.clone();
                let build_queue = build_queue.clone();
                let output_cache = output_cache.clone();
                let status = status.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(conn) => conn,
                        Err(err) => {
                            eprintln!("connection error: {err:#}");
                            return;
                        }
                    };

                    if let Err(err) = connection::handle_incoming(
                        conn,
                        access_policy,
                        ticket_store,
                        build_queue,
                        output_cache,
                        status,
                    )
                    .await
                    {
                        eprintln!("connection error: {err:#}");
                    }
                });
            }
        }
    }
}

async fn wait_closed(conn: &Connection) {
    let _ = tokio::time::timeout(CLOSE_TIMEOUT, conn.closed()).await;
}

async fn send_error(send: &mut SendStream, message: &str) -> Result<()> {
    wire::write_json(
        send,
        &Message::Error(ErrorMessage {
            message: message.to_string(),
        }),
    )
    .await
}

async fn read_message(recv: &mut RecvStream) -> Result<Message> {
    read_message_with_timeout(recv, CONTROL_TIMEOUT).await
}

async fn read_message_with_timeout(recv: &mut RecvStream, timeout: Duration) -> Result<Message> {
    tokio::time::timeout(timeout, wire::read_json(recv))
        .await
        .context("read timed out")?
}
