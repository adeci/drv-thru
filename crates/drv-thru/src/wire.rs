use anyhow::{Context, Result, bail};
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Serialize, de::DeserializeOwned};

const MAX_MESSAGE_LEN: usize = 1024 * 1024;

pub async fn write_json<T: Serialize>(send: &mut SendStream, message: &T) -> Result<()> {
    let body = serde_json::to_vec(message).context("encode wire message")?;
    if body.len() > MAX_MESSAGE_LEN {
        bail!("wire message too large: {} bytes", body.len());
    }

    let len = u32::try_from(body.len()).context("wire message length overflow")?;
    send.write_all(&len.to_be_bytes()).await?;
    send.write_all(&body).await?;
    Ok(())
}

pub async fn read_json<T: DeserializeOwned>(recv: &mut RecvStream) -> Result<T> {
    let mut len = [0; 4];
    recv.read_exact(&mut len)
        .await
        .context("read message length")?;

    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_MESSAGE_LEN {
        bail!("wire message too large: {len} bytes");
    }

    let mut body = vec![0; len];
    recv.read_exact(&mut body)
        .await
        .context("read message body")?;
    serde_json::from_slice(&body).context("decode wire message")
}
