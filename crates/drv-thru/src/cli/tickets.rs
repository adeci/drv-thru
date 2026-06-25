use std::{
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use iroh::EndpointId;

use crate::{
    config::{parse_byte_count, parse_duration},
    ticket,
};

use super::data_dir;

#[derive(Subcommand)]
pub(super) enum TicketCommand {
    Create {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, help = "Bind this ticket to one client endpoint id.")]
        bind_client: Option<EndpointId>,
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
    List {
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    Inspect {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        ticket: ticket::BuildTicket,
    },
    Reveal {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        ticket_id: String,
    },
    Revoke {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        ticket_id: String,
    },
}

pub(super) fn run(command: TicketCommand) -> Result<()> {
    match command {
        TicketCommand::Create {
            data_dir,
            name,
            bind_client,
            expires,
            uses,
            unlimited,
            max_build_time,
            max_upload_bytes,
        } => create(TicketCreateArgs {
            data_dir,
            name,
            bind_client,
            expires,
            uses,
            unlimited,
            max_build_time,
            max_upload_bytes,
        }),
        TicketCommand::List { data_dir } => list(data_dir),
        TicketCommand::Inspect { data_dir, ticket } => inspect(data_dir, &ticket),
        TicketCommand::Reveal {
            data_dir,
            ticket_id,
        } => reveal(data_dir, &ticket_id),
        TicketCommand::Revoke {
            data_dir,
            ticket_id,
        } => revoke(data_dir, &ticket_id),
    }
}

struct TicketCreateArgs {
    data_dir: Option<PathBuf>,
    name: Option<String>,
    bind_client: Option<EndpointId>,
    expires: String,
    uses: Option<String>,
    unlimited: bool,
    max_build_time: String,
    max_upload_bytes: String,
}

fn create(args: TicketCreateArgs) -> Result<()> {
    let data_dir = data_dir::optional(args.data_dir)?;
    let expires_after = parse_duration(&args.expires)
        .with_context(|| format!("parse --expires {}", args.expires))?;
    let uses_remaining = parse_ticket_uses(args.uses.as_deref(), args.unlimited)?;
    parse_duration(&args.max_build_time)
        .with_context(|| format!("parse --max-build-time {}", args.max_build_time))?;
    parse_byte_count(&args.max_upload_bytes)
        .with_context(|| format!("parse --max-upload-bytes {}", args.max_upload_bytes))?;

    let server_addr = ticket::load_server_addr(&data_dir).with_context(|| {
        format!(
            "read server state in {}; run as root, a wheel user, or pass --data-dir",
            data_dir.display()
        )
    })?;
    let store = ticket::TicketStore::new(&data_dir);
    let ticket = store
        .create(
            &server_addr,
            ticket::CreateTicket {
                name: args.name,
                bound_client: args.bind_client.map(|id| id.to_string()),
                expires_after,
                uses_remaining,
                max_build_time: args.max_build_time,
                max_upload_bytes: args.max_upload_bytes,
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

fn list(data_dir: Option<PathBuf>) -> Result<()> {
    let data_dir = data_dir::optional(data_dir)?;
    let store = ticket::TicketStore::new(&data_dir);
    let records = store.records().with_context(|| {
        format!(
            "read ticket state in {}; run as root, a wheel user, or pass --data-dir",
            data_dir.display()
        )
    })?;

    if records.is_empty() {
        println!("no tickets");
        return Ok(());
    }

    let now = now_unix_secs()?;
    println!("id\tname\tstatus\tuses\texpires_unix\tbound_client");
    for (id, record) in records {
        println!(
            "{id}\t{}\t{}\t{}\t{}\t{}",
            record.name.as_deref().unwrap_or("-"),
            ticket_record_status(&record, now),
            format_uses(record.uses_remaining),
            record.expires_at_unix,
            record.bound_client.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

fn inspect(data_dir: Option<PathBuf>, build_ticket: &ticket::BuildTicket) -> Result<()> {
    let data_dir = data_dir::optional(data_dir)?;
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
        Some(record) => print_ticket_record(record),
        None => println!("store: ticket record not found"),
    }
    Ok(())
}

fn print_ticket_record(record: ticket::TicketRecord) {
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

fn reveal(data_dir: Option<PathBuf>, ticket_id: &str) -> Result<()> {
    let data_dir = data_dir::optional(data_dir)?;
    let store = ticket::TicketStore::new(&data_dir);
    let record = store
        .record(ticket_id)
        .with_context(|| {
            format!(
                "read ticket state in {}; run as root, a wheel user, or pass --data-dir",
                data_dir.display()
            )
        })?
        .with_context(|| format!("ticket not found: {ticket_id}"))?;
    println!("{}", record.encoded_ticket);
    Ok(())
}

fn revoke(data_dir: Option<PathBuf>, ticket_id: &str) -> Result<()> {
    let data_dir = data_dir::optional(data_dir)?;
    let store = ticket::TicketStore::new(&data_dir);
    store.revoke(ticket_id).with_context(|| {
        format!(
            "revoke ticket in {}; run as root, a wheel user, or pass --data-dir",
            data_dir.display()
        )
    })?;
    println!("revoked ticket: {ticket_id}");
    Ok(())
}

fn ticket_record_status(record: &ticket::TicketRecord, now: u64) -> &'static str {
    if record.revoked {
        "revoked"
    } else if now >= record.expires_at_unix {
        "expired"
    } else if matches!(record.uses_remaining, Some(0)) {
        "exhausted"
    } else {
        "active"
    }
}

fn now_unix_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
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
