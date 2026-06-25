mod access;
mod cache;
mod cli;
mod client;
mod client_cache;
mod client_status;
mod config;
mod import_helper;
mod keys;
mod nix;
mod process_lock;
mod protocol;
mod server;
mod state;
mod ticket;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}
