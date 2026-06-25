use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::{
    io::AsyncWriteExt,
    process::{Child, ChildStdin, Command},
};

use crate::{client_status::ClientStatus, protocol::OutputMode};

pub(super) enum LogRenderer {
    Plain,
    Nom(NomRenderer),
    Disabled,
}

impl LogRenderer {
    pub(super) fn new(output_mode: OutputMode) -> Result<Self> {
        match output_mode {
            OutputMode::Plain => Ok(Self::Plain),
            OutputMode::Nom => Ok(Self::Nom(NomRenderer::new()?)),
        }
    }

    pub(super) async fn print(&mut self, line: &str, status: &ClientStatus) -> Result<()> {
        match self {
            Self::Plain => {
                status.suspend(|| eprintln!("{line}"));
                Ok(())
            }
            Self::Nom(nom) => nom.print(line).await,
            Self::Disabled => Ok(()),
        }
    }

    pub(super) async fn finish(&mut self) -> Result<()> {
        match self {
            Self::Plain | Self::Disabled => Ok(()),
            Self::Nom(nom) => nom.finish().await,
        }
    }
}

pub(super) struct NomRenderer {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl NomRenderer {
    fn new() -> Result<Self> {
        let mut child = Command::new("nom")
            .arg("--json")
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .context("start `nom --json`; install nom or use `--no-nom`")?;
        let stdin = child.stdin.take().context("nom stdin not piped")?;

        Ok(Self {
            child,
            stdin: Some(stdin),
        })
    }

    async fn print(&mut self, line: &str) -> Result<()> {
        let stdin = self.stdin.as_mut().context("nom stdin is closed")?;
        stdin
            .write_all(line.as_bytes())
            .await
            .context("write log line to nom")?;
        stdin
            .write_all(b"\n")
            .await
            .context("write log newline to nom")?;
        Ok(())
    }

    async fn finish(&mut self) -> Result<()> {
        drop(self.stdin.take());
        let status = self.child.wait().await.context("wait for nom")?;
        if !status.success() {
            bail!("nom exited with {status}");
        }
        Ok(())
    }
}
