use std::path::PathBuf;

use anyhow::Result;
use iroh::{EndpointAddr, EndpointId, RelayUrl};

use crate::{nix, protocol::OutputMode, ticket::BuildTicket};

mod logs;
mod session;
mod summary;

pub enum BuildAuth {
    TrustedClient {
        server_id: EndpointId,
        relay_url: Option<RelayUrl>,
    },
    Ticket(BuildTicket),
}

impl BuildAuth {
    pub(super) fn server_addr(&self) -> EndpointAddr {
        match self {
            BuildAuth::TrustedClient {
                server_id,
                relay_url,
            } => match relay_url {
                Some(relay_url) => EndpointAddr::new(*server_id).with_relay_url(relay_url.clone()),
                None => EndpointAddr::new(*server_id),
            },
            BuildAuth::Ticket(ticket) => ticket.addr().clone(),
        }
    }
}

pub async fn build(
    installable: String,
    auth: Option<BuildAuth>,
    key_file: Option<PathBuf>,
    output_mode: OutputMode,
    nar_fetches: Option<usize>,
    eval_options: nix::EvalOptions,
    rebuild: bool,
) -> Result<()> {
    session::build(
        installable,
        auth,
        key_file,
        output_mode,
        nar_fetches,
        eval_options,
        rebuild,
    )
    .await
}
