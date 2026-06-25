use std::time::Duration;

use anyhow::Result;
use iroh::{
    EndpointId,
    endpoint::{RecvStream, SendStream},
};

use crate::{
    access::AccessPolicy,
    config::{parse_byte_count, parse_duration},
    protocol::{AuthOk, Message, wire},
    ticket::TicketStore,
};

use super::{read_message, send_error};

pub(super) struct AuthorizedConnection {
    pub(super) client_label: String,
    pub(super) max_build_time: Option<Duration>,
    pub(super) max_upload_bytes: Option<u64>,
    ticket_secret: Option<[u8; 32]>,
}

pub(super) async fn authorize_connection(
    peer: &EndpointId,
    access_policy: &AccessPolicy,
    ticket_store: &TicketStore,
    send: &mut SendStream,
    recv: &mut RecvStream,
    builder_public_key: &str,
) -> Result<Option<AuthorizedConnection>> {
    match read_message(recv).await? {
        Message::AuthTrustedClient => {
            authorize_trusted_client(peer, access_policy, send, builder_public_key).await
        }
        Message::AuthTicket(auth) => {
            authorize_ticket(peer, ticket_store, send, &auth.secret, builder_public_key).await
        }
        message => {
            send_error(send, &format!("expected auth message, got {message:?}")).await?;
            Ok(None)
        }
    }
}

pub(super) async fn redeem_ticket_if_needed(
    mut authorized: AuthorizedConnection,
    peer: &EndpointId,
    ticket_store: &TicketStore,
    send: &mut SendStream,
) -> Result<Option<AuthorizedConnection>> {
    let Some(secret) = authorized.ticket_secret.take() else {
        return Ok(Some(authorized));
    };

    let record = match ticket_store.redeem(&secret, peer) {
        Ok(record) => record,
        Err(err) => {
            send_error(send, &err.to_string()).await?;
            return Ok(None);
        }
    };

    authorized.max_build_time = Some(parse_duration(&record.max_build_time)?);
    authorized.max_upload_bytes = Some(parse_byte_count(&record.max_upload_bytes)?);
    Ok(Some(authorized))
}

async fn authorize_trusted_client(
    peer: &EndpointId,
    access_policy: &AccessPolicy,
    send: &mut SendStream,
    builder_public_key: &str,
) -> Result<Option<AuthorizedConnection>> {
    let Some(client) = access_policy.authorize(peer) else {
        send_error(send, "client is not trusted").await?;
        return Ok(None);
    };

    match &client.name {
        Some(name) => println!("accepted trusted client {name} ({peer})"),
        None => println!("accepted trusted client {peer}"),
    }

    let max_build_time = client
        .policy
        .max_build_time
        .as_deref()
        .map(parse_duration)
        .transpose()?;
    let max_upload_bytes = client
        .policy
        .max_upload_bytes
        .as_deref()
        .map(parse_byte_count)
        .transpose()?;

    let client_name = client.name.clone();
    let client_label = client
        .name
        .as_deref()
        .map_or_else(|| format!("client:{peer}"), |name| format!("client:{name}"));

    write_auth_ok(send, client_name, builder_public_key).await?;
    Ok(Some(AuthorizedConnection {
        client_label,
        max_build_time,
        max_upload_bytes,
        ticket_secret: None,
    }))
}

async fn authorize_ticket(
    peer: &EndpointId,
    ticket_store: &TicketStore,
    send: &mut SendStream,
    secret: &[u8; 32],
    builder_public_key: &str,
) -> Result<Option<AuthorizedConnection>> {
    let record = match ticket_store.check(secret, peer) {
        Ok(record) => record,
        Err(err) => {
            send_error(send, &err.to_string()).await?;
            return Ok(None);
        }
    };

    match &record.name {
        Some(name) => println!("accepted ticket {name} ({peer})"),
        None => println!("accepted ticket ({peer})"),
    }

    let max_build_time = Some(parse_duration(&record.max_build_time)?);
    let max_upload_bytes = Some(parse_byte_count(&record.max_upload_bytes)?);
    let client_name = record.name.clone();
    let client_label = record
        .name
        .as_deref()
        .map_or_else(|| format!("ticket:{peer}"), |name| format!("ticket:{name}"));

    write_auth_ok(send, client_name, builder_public_key).await?;
    Ok(Some(AuthorizedConnection {
        client_label,
        max_build_time,
        max_upload_bytes,
        ticket_secret: Some(*secret),
    }))
}

async fn write_auth_ok(
    send: &mut SendStream,
    client_name: Option<String>,
    builder_public_key: &str,
) -> Result<()> {
    wire::write_json(
        send,
        &Message::AuthOk(AuthOk {
            client_name,
            builder_public_key: builder_public_key.to_string(),
        }),
    )
    .await
}
