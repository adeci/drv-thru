use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use iroh::{EndpointId, RelayUrl};

use crate::{
    client::{self, BuildAuth},
    import_helper, keys, nix,
    protocol::OutputMode,
    server, ticket,
};

mod builders;
mod data_dir;
mod status;
mod tickets;

#[derive(Parser)]
#[command(name = "drv-thru")]
#[command(about = "Remote Nix builds over Iroh")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    Serve {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long = "trusted-client")]
        trusted_client: Vec<EndpointId>,
    },
    Build {
        installable: String,
        #[arg(
            long,
            value_name = "NAME",
            help = "Use a named builder from /etc/drv-thru/builders.json."
        )]
        builder: Option<String>,
        #[arg(long)]
        server: Option<EndpointId>,
        #[arg(long)]
        relay_url: Option<RelayUrl>,
        #[arg(long)]
        ticket: Option<ticket::BuildTicket>,
        #[arg(
            long,
            help = "Client key file. Trusted builds default to ~/.config/drv-thru/secret.key; ticket builds default to an ephemeral key."
        )]
        key_file: Option<PathBuf>,
        #[arg(long)]
        no_nom: bool,
        #[arg(
            long,
            help = "Parallel NAR payload fetches for local cache mirroring. Defaults to auto; DRV_THRU_NAR_FETCHES is also honored."
        )]
        nar_fetches: Option<usize>,
        #[arg(long, help = "Pass --impure to client-side Nix evaluation.")]
        impure: bool,
        #[arg(long, help = "Pass --refresh to client-side Nix evaluation.")]
        refresh: bool,
        #[arg(
            long = "override-input",
            value_names = ["INPUT_PATH", "FLAKE_URL"],
            num_args = 2,
            help = "Pass --override-input to client-side Nix evaluation. Can be repeated."
        )]
        override_input: Vec<String>,
        #[arg(long, help = "Ask the builder to rebuild and check the derivation.")]
        rebuild: bool,
    },
    Ticket {
        #[command(subcommand)]
        command: tickets::TicketCommand,
    },
    Status {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        watch: bool,
    },
    #[command(name = "import-helper", hide = true)]
    ImportHelper {
        #[command(subcommand)]
        command: ImportHelperCommand,
    },
}

#[derive(Subcommand)]
enum KeyCommand {
    Show {
        #[arg(long)]
        key_file: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum ImportHelperCommand {
    Serve {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long = "trusted-public-key-file")]
        trusted_public_key_file: PathBuf,
    },
}

pub async fn run() -> Result<()> {
    dispatch(Cli::parse().command).await
}

async fn dispatch(command: Command) -> Result<()> {
    match command {
        Command::Key {
            command: KeyCommand::Show { key_file },
        } => show_key(key_file),
        Command::Serve {
            data_dir,
            config,
            trusted_client,
        } => serve(data_dir, config, trusted_client).await,
        Command::Build {
            installable,
            builder,
            server,
            relay_url,
            ticket,
            key_file,
            no_nom,
            nar_fetches,
            impure,
            refresh,
            override_input,
            rebuild,
        } => {
            let output_mode = if no_nom {
                OutputMode::Plain
            } else {
                OutputMode::Nom
            };
            build(BuildCommandArgs {
                installable,
                builder,
                server,
                relay_url,
                ticket,
                key_file,
                output_mode,
                nar_fetches,
                impure,
                refresh,
                override_input,
                rebuild,
            })
            .await
        }
        Command::Ticket { command } => tickets::run(command),
        Command::Status { data_dir, watch } => status::show(data_dir, watch).await,
        Command::ImportHelper { command } => match command {
            ImportHelperCommand::Serve {
                socket,
                trusted_public_key_file,
            } => {
                let trusted_public_keys =
                    import_helper::load_trusted_public_keys(&trusted_public_key_file)?;
                import_helper::serve(socket, trusted_public_keys).await
            }
        },
    }
}

fn show_key(key_file: Option<PathBuf>) -> Result<()> {
    let path = match key_file {
        Some(path) => path,
        None => keys::default_client_key_path()?,
    };
    let key = keys::load_or_create(path)?;
    println!("{}", key.public());
    Ok(())
}

async fn serve(
    data_dir: Option<PathBuf>,
    config: Option<PathBuf>,
    trusted_client: Vec<EndpointId>,
) -> Result<()> {
    if data_dir.is_some() && config.is_some() {
        bail!("--data-dir and --config cannot be used together");
    }
    if !trusted_client.is_empty() && config.is_some() {
        bail!("--trusted-client cannot be used with --config");
    }

    match (data_dir, config) {
        (data_dir, None) => {
            let data_dir = data_dir::optional(data_dir)?;
            server::serve(server::ServeMode::DataDir {
                data_dir,
                trusted_clients: trusted_client,
            })
            .await
        }
        (None, Some(config)) => server::serve(server::ServeMode::Config(config)).await,
        (Some(_), Some(_)) => unreachable!("checked above"),
    }
}

struct BuildCommandArgs {
    installable: String,
    builder: Option<String>,
    server: Option<EndpointId>,
    relay_url: Option<RelayUrl>,
    ticket: Option<ticket::BuildTicket>,
    key_file: Option<PathBuf>,
    output_mode: OutputMode,
    nar_fetches: Option<usize>,
    impure: bool,
    refresh: bool,
    override_input: Vec<String>,
    rebuild: bool,
}

async fn build(args: BuildCommandArgs) -> Result<()> {
    if args.nar_fetches == Some(0) {
        bail!("--nar-fetches must be at least 1");
    }
    let auth = build_auth(
        args.builder.as_deref(),
        args.server,
        args.relay_url,
        args.ticket,
    )?;
    client::build(
        args.installable,
        auth,
        args.key_file,
        args.output_mode,
        args.nar_fetches,
        eval_options(args.impure, args.refresh, &args.override_input)?,
        args.rebuild,
    )
    .await
}

fn eval_options(
    impure: bool,
    refresh: bool,
    override_input: &[String],
) -> Result<nix::EvalOptions> {
    let pairs = override_input.chunks_exact(2);
    if !pairs.remainder().is_empty() {
        bail!("--override-input requires INPUT_PATH and FLAKE_URL");
    }
    let override_inputs = pairs
        .map(|chunk| nix::OverrideInput {
            input_path: chunk[0].clone(),
            flake_url: chunk[1].clone(),
        })
        .collect::<Vec<_>>();

    Ok(nix::EvalOptions {
        impure,
        refresh,
        override_inputs,
    })
}

fn build_auth(
    builder: Option<&str>,
    server: Option<EndpointId>,
    relay_url: Option<RelayUrl>,
    ticket: Option<ticket::BuildTicket>,
) -> Result<Option<BuildAuth>> {
    if builder.is_some() && (server.is_some() || relay_url.is_some() || ticket.is_some()) {
        bail!("--builder cannot be used with --server, --relay-url, or --ticket");
    }
    if ticket.is_some() && relay_url.is_some() {
        bail!("--relay-url cannot be used with --ticket");
    }
    if server.is_none() && relay_url.is_some() {
        bail!("--relay-url requires --server");
    }

    match (builder, server, ticket) {
        (Some(name), None, None) => builders::load(name).map(Some),
        (None, Some(server_id), None) => Ok(Some(BuildAuth::TrustedClient {
            server_id,
            relay_url,
        })),
        (None, None, Some(ticket)) => Ok(Some(BuildAuth::Ticket(ticket))),
        (None, None, None) => Ok(None),
        (None, Some(_), Some(_)) => bail!("--server and --ticket cannot be used together"),
        (Some(_), _, _) => unreachable!("checked above"),
    }
}
