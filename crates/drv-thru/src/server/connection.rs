use std::sync::Arc;

use anyhow::{Context, Result, bail};
use iroh::{
    EndpointId,
    endpoint::{Connection, RecvStream, SendStream},
};
use tokio::sync::Semaphore;

use crate::{
    access::AccessPolicy,
    protocol::{BuildRequest, Hello, Message, VERSION, wire},
    ticket::TicketStore,
};

use super::{
    CLIENT_NIX_TIMEOUT, auth, build, output_cache::OutputCache, read_message,
    read_message_with_timeout, send_error, status, wait_closed,
};

pub(super) async fn handle_incoming(
    conn: Connection,
    access_policy: AccessPolicy,
    ticket_store: TicketStore,
    build_queue: Arc<Semaphore>,
    output_cache: Arc<OutputCache>,
    status_registry: status::StatusRegistry,
) -> Result<()> {
    let peer = conn.remote_id();
    let (mut send, mut recv) = conn.accept_bi().await?;
    read_hello(&peer, &mut recv).await?;

    let Some(authorized) = auth::authorize_connection(
        &peer,
        &access_policy,
        &ticket_store,
        &mut send,
        &mut recv,
        output_cache.public_key(),
    )
    .await?
    else {
        return finish_control(&mut send, &conn).await;
    };

    let Some(build) = read_build_or_report(&mut send, &mut recv, &conn).await? else {
        return Ok(());
    };
    let Some(authorized) =
        auth::redeem_ticket_if_needed(authorized, &peer, &ticket_store, &mut send).await?
    else {
        return finish_control(&mut send, &conn).await;
    };

    let request_id =
        status_registry.enqueue(authorized.client_label.clone(), build.installable.clone());
    send_build_queued(&mut send, &status_registry, &request_id).await?;

    let run_outcome = run_when_permitted(
        QueuedRun {
            conn: &conn,
            send: &mut send,
            recv: &mut recv,
            build_queue,
            output_cache: output_cache.as_ref(),
            status_registry: &status_registry,
            request_id: &request_id,
        },
        build,
        authorized,
    )
    .await?;

    let RunOutcome::BuildFinished(build_result) = run_outcome else {
        return Ok(());
    };
    record_build_result(&mut send, &status_registry, &request_id, build_result).await?;
    finish_control(&mut send, &conn).await
}

async fn read_hello(peer: &EndpointId, recv: &mut RecvStream) -> Result<()> {
    match read_message(recv).await? {
        Message::Hello(hello) => check_hello(peer, &hello),
        message => bail!("expected hello, got {message:?}"),
    }
}

fn check_hello(peer: &EndpointId, hello: &Hello) -> Result<()> {
    if hello.version != VERSION {
        bail!("unsupported protocol version: {}", hello.version);
    }

    let claimed_peer = hello
        .node_id
        .parse::<EndpointId>()
        .with_context(|| format!("parse hello node id: {}", hello.node_id))?;
    if &claimed_peer != peer {
        bail!("hello node id {claimed_peer} does not match connection peer {peer}");
    }
    Ok(())
}

async fn read_build_or_report(
    send: &mut SendStream,
    recv: &mut RecvStream,
    conn: &Connection,
) -> Result<Option<build::CheckedBuildRequest>> {
    let request = match read_message_with_timeout(recv, CLIENT_NIX_TIMEOUT).await? {
        Message::BuildRequest(request) => request,
        message => bail!("expected build request, got {message:?}"),
    };

    match read_checked_build(recv, request).await {
        Ok(build) => Ok(Some(build)),
        Err(err) => {
            send_error(send, &err.to_string()).await?;
            finish_control(send, conn).await?;
            Ok(None)
        }
    }
}

async fn read_checked_build(
    recv: &mut RecvStream,
    request: BuildRequest,
) -> Result<build::CheckedBuildRequest> {
    build::read_checked_build_request(recv, request).await
}

async fn send_build_queued(
    send: &mut SendStream,
    status_registry: &status::StatusRegistry,
    request_id: &str,
) -> Result<()> {
    if let Err(err) = wire::write_json(send, &Message::BuildQueued).await {
        status_registry.finish(
            request_id,
            status::BuildResult::Error,
            Some(err.to_string()),
        );
        return Err(err);
    }
    Ok(())
}

struct QueuedRun<'a> {
    conn: &'a Connection,
    send: &'a mut SendStream,
    recv: &'a mut RecvStream,
    build_queue: Arc<Semaphore>,
    output_cache: &'a OutputCache,
    status_registry: &'a status::StatusRegistry,
    request_id: &'a str,
}

#[derive(Debug)]
enum RunOutcome {
    QueueClosed,
    BuildFinished(Result<bool>),
}

async fn run_when_permitted(
    run: QueuedRun<'_>,
    build: build::CheckedBuildRequest,
    authorized: auth::AuthorizedConnection,
) -> Result<RunOutcome> {
    let Ok(_permit) = run.build_queue.acquire_owned().await else {
        run.status_registry.finish(
            run.request_id,
            status::BuildResult::Error,
            Some("build queue is closed".to_string()),
        );
        send_error(&mut *run.send, "build queue is closed").await?;
        finish_control(&mut *run.send, run.conn).await?;
        return Ok(RunOutcome::QueueClosed);
    };

    run.status_registry.start(run.request_id);
    let build_result = build::run_queued_build(
        run.conn,
        &mut *run.send,
        &mut *run.recv,
        build,
        authorized,
        run.output_cache,
        build::BuildStatusScope {
            registry: run.status_registry,
            request_id: run.request_id,
        },
    )
    .await;
    Ok(RunOutcome::BuildFinished(build_result))
}

async fn record_build_result(
    send: &mut SendStream,
    status_registry: &status::StatusRegistry,
    request_id: &str,
    build_result: Result<bool>,
) -> Result<()> {
    match build_result {
        Ok(true) => status_registry.finish(request_id, status::BuildResult::Success, None),
        Ok(false) => status_registry.finish(
            request_id,
            status::BuildResult::Failed,
            Some("nix build failed".to_string()),
        ),
        Err(err) => {
            let message = err.to_string();
            status_registry.finish(
                request_id,
                status::BuildResult::Error,
                Some(message.clone()),
            );
            send_error(send, &message).await?;
        }
    }
    Ok(())
}

async fn finish_control(send: &mut SendStream, conn: &Connection) -> Result<()> {
    send.finish()?;
    wait_closed(conn).await;
    Ok(())
}
