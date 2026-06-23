mod access;
mod cli;
mod client;
mod client_status;
mod config;
mod keys;
mod nix;
mod proto;
mod server;
mod ticket;
mod wire;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cli::run().await
}
