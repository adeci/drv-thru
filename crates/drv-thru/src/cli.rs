use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};

use crate::{
    client::{self, BuildAuth},
    config::{parse_byte_count, parse_duration},
    import_helper, keys,
    proto::OutputMode,
    server, ticket,
};

const SYSTEM_DATA_DIR: &str = "/var/lib/drv-thru";

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
        trusted_client: Vec<iroh::EndpointId>,
    },
    Build {
        installable: String,
        #[arg(long)]
        server: Option<iroh::EndpointId>,
        #[arg(long)]
        relay_url: Option<iroh::RelayUrl>,
        #[arg(long)]
        ticket: Option<ticket::BuildTicket>,
        #[arg(
            long,
            help = "Client key file. Trusted builds default to ~/.config/drv-thru/secret.key; ticket builds default to an ephemeral key."
        )]
        key_file: Option<PathBuf>,
        #[arg(long)]
        no_nom: bool,
    },
    Ticket {
        #[command(subcommand)]
        command: TicketCommand,
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
    },
}

#[derive(Subcommand)]
enum TicketCommand {
    Create {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value = "2h")]
        expires: String,
        #[arg(long)]
        uses: Option<String>,
        #[arg(long)]
        unlimited: bool,
        #[arg(long, default_value = "30m")]
        max_build_time: String,
        #[arg(long, default_value = "20G")]
        max_upload_bytes: String,
    },
    Inspect {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        ticket: ticket::BuildTicket,
    },
}

pub async fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Key {
            command: KeyCommand::Show { key_file },
        } => {
            let path = match key_file {
                Some(path) => path,
                None => keys::default_client_key_path()?,
            };
            let key = keys::load_or_create(path)?;
            println!("{}", key.public());
            Ok(())
        }
        Command::Serve {
            data_dir,
            config,
            trusted_client,
        } => {
            if data_dir.is_some() && config.is_some() {
                bail!("--data-dir and --config cannot be used together");
            }
            if !trusted_client.is_empty() && config.is_some() {
                bail!("--trusted-client cannot be used with --config");
            }
            match (data_dir, config) {
                (data_dir, None) => {
                    let data_dir = data_dir.unwrap_or(default_data_dir()?);
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
        Command::Build {
            installable,
            server,
            relay_url,
            ticket,
            key_file,
            no_nom,
        } => {
            let output_mode = if no_nom {
                OutputMode::Plain
            } else {
                OutputMode::Nom
            };
            let auth = build_auth(server, relay_url, ticket)?;
            client::build(installable, auth, key_file, output_mode).await
        }
        Command::Ticket { command } => match command {
            TicketCommand::Create {
                data_dir,
                name,
                expires,
                uses,
                unlimited,
                max_build_time,
                max_upload_bytes,
            } => create_ticket(
                data_dir,
                name,
                expires,
                uses,
                unlimited,
                max_build_time,
                max_upload_bytes,
            ),
            TicketCommand::Inspect { data_dir, ticket } => inspect_ticket(data_dir, ticket),
        },
        Command::ImportHelper {
            command: ImportHelperCommand::Serve { socket },
        } => import_helper::serve(socket).await,
    }
}

fn default_data_dir() -> Result<PathBuf> {
    let system_data_dir = PathBuf::from(SYSTEM_DATA_DIR);
    if ensure_data_dir_accessible(&system_data_dir).is_ok() {
        return Ok(system_data_dir);
    }

    let user_data_dir = match std::env::var_os("XDG_STATE_HOME") {
        Some(path) => PathBuf::from(path).join("drv-thru"),
        None => {
            let home = std::env::var_os("HOME").context("HOME is not set; pass --data-dir")?;
            PathBuf::from(home).join(".local/state/drv-thru")
        }
    };
    ensure_data_dir_accessible(&user_data_dir)?;
    Ok(user_data_dir)
}

fn ensure_data_dir_accessible(path: &Path) -> Result<()> {
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

fn build_auth(
    server: Option<iroh::EndpointId>,
    relay_url: Option<iroh::RelayUrl>,
    ticket: Option<ticket::BuildTicket>,
) -> Result<BuildAuth> {
    if ticket.is_some() && relay_url.is_some() {
        bail!("--relay-url cannot be used with --ticket");
    }
    if server.is_none() && relay_url.is_some() {
        bail!("--relay-url requires --server");
    }

    match (server, ticket) {
        (Some(server_id), None) => Ok(BuildAuth::TrustedClient {
            server_id,
            relay_url,
        }),
        (None, Some(ticket)) => Ok(BuildAuth::Ticket(ticket)),
        (None, None) => bail!("build requires either --server or --ticket"),
        (Some(_), Some(_)) => bail!("--server and --ticket cannot be used together"),
    }
}

fn create_ticket(
    data_dir: Option<PathBuf>,
    name: Option<String>,
    expires: String,
    uses: Option<String>,
    unlimited: bool,
    max_build_time: String,
    max_upload_bytes: String,
) -> Result<()> {
    let data_dir = data_dir.unwrap_or(default_data_dir()?);
    let expires_after =
        parse_duration(&expires).with_context(|| format!("parse --expires {expires}"))?;
    let uses_remaining = parse_ticket_uses(uses.as_deref(), unlimited)?;
    parse_duration(&max_build_time)
        .with_context(|| format!("parse --max-build-time {max_build_time}"))?;
    parse_byte_count(&max_upload_bytes)
        .with_context(|| format!("parse --max-upload-bytes {max_upload_bytes}"))?;

    let server_addr = ticket::load_server_addr(&data_dir).with_context(|| {
        format!(
            "read server state in {}; run as root, a wheel user, or pass --data-dir",
            data_dir.display()
        )
    })?;
    let store = ticket::TicketStore::new(&data_dir);
    let ticket = store
        .create(
            server_addr,
            ticket::CreateTicket {
                name,
                expires_after,
                uses_remaining,
                max_build_time,
                max_upload_bytes,
            },
        )
        .with_context(|| {
            format!(
                "write ticket state in {}; run as root, a wheel user, or pass --data-dir",
                data_dir.display()
            )
        })?;

    println!("{ticket}");
    Ok(())
}

fn inspect_ticket(data_dir: Option<PathBuf>, build_ticket: ticket::BuildTicket) -> Result<()> {
    let data_dir = data_dir.unwrap_or(default_data_dir()?);
    let id = build_ticket.id();
    println!("ticket: {build_ticket}");
    println!("ticket id: {id}");
    println!("server endpoint id: {}", build_ticket.addr().id);
    for relay_url in build_ticket.addr().relay_urls() {
        println!("server relay url: {relay_url}");
    }
    for direct_addr in build_ticket.addr().ip_addrs() {
        println!("server direct addr: {direct_addr}");
    }

    let store = ticket::TicketStore::new(&data_dir);
    match store.record(&id).with_context(|| {
        format!(
            "read ticket state in {}; run as root, a wheel user, or pass --data-dir",
            data_dir.display()
        )
    })? {
        Some(record) => {
            println!("name: {}", record.name.as_deref().unwrap_or("<none>"));
            println!("created unix: {}", record.created_at_unix);
            println!("expires unix: {}", record.expires_at_unix);
            println!("uses remaining: {}", format_uses(record.uses_remaining));
            println!("max build time: {}", record.max_build_time);
            println!("max upload bytes: {}", record.max_upload_bytes);
            if let Some(bound_client) = record.bound_client {
                println!("bound client: {bound_client}");
            }
            println!("revoked: {}", record.revoked);
        }
        None => println!("store: ticket record not found"),
    }
    Ok(())
}

fn parse_ticket_uses(uses: Option<&str>, unlimited: bool) -> Result<Option<u64>> {
    if unlimited {
        if uses.is_some() {
            bail!("--uses and --unlimited cannot be used together");
        }
        return Ok(None);
    }

    let Some(uses) = uses else {
        return Ok(Some(1));
    };
    if uses.eq_ignore_ascii_case("unlimited") {
        return Ok(None);
    }

    let uses = uses
        .parse::<u64>()
        .with_context(|| format!("parse --uses {uses}"))?;
    if uses == 0 {
        bail!("--uses must be at least 1 or unlimited");
    }
    Ok(Some(uses))
}

fn format_uses(uses: Option<u64>) -> String {
    match uses {
        Some(uses) => uses.to_string(),
        None => "unlimited".to_string(),
    }
}
