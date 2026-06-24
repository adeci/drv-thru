use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::Path,
    process::{Output, Stdio},
};

use anyhow::{Context, Result, bail};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, BufReader},
    process::Command,
};

use crate::proto::OutputMode;

const STORE_PREFIX: &str = "/nix/store/";
const HASH_LEN: usize = 32;
const NIX_BASE32: &str = "0123456789abcdfghijklmnpqrsvwxyz";
const PATH_ARG_CHUNK_SIZE: usize = 512;

#[derive(Clone, PartialEq, Eq)]
pub struct StorePath(String);

impl StorePath {
    pub fn new(path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        validate_store_path(&path)?;
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

pub async fn resolve_derivation(installable: &str) -> Result<StorePath> {
    let output = run_command("nix", &["path-info", "--derivation", installable]).await?;
    let path = output
        .lines()
        .find_map(non_empty_line)
        .context("nix did not return a derivation path")?;
    StorePath::new(path)
}

pub async fn resolve_outputs(installable: &str) -> Result<Vec<StorePath>> {
    let output = run_command("nix", &["build", "--dry-run", "--json", installable]).await?;
    parse_build_plan_outputs(&output)
}

fn parse_build_plan_outputs(output: &str) -> Result<Vec<StorePath>> {
    let plan: Vec<BuildPlanEntry> =
        serde_json::from_str(output).context("parse nix build dry-run output")?;
    if plan.len() != 1 {
        bail!("expected one build plan entry, got {}", plan.len());
    }
    plan.into_iter()
        .next()
        .expect("checked length")
        .outputs
        .into_values()
        .map(StorePath::new)
        .collect()
}

#[derive(serde::Deserialize)]
struct BuildPlanEntry {
    outputs: BTreeMap<String, String>,
}

pub async fn closure(path: &StorePath) -> Result<Vec<StorePath>> {
    query_closure(std::slice::from_ref(path)).await
}

pub struct RealiseResult {
    pub success: bool,
    pub output_paths: Vec<StorePath>,
}

pub trait LogSink {
    fn log_line(&mut self, line: String) -> impl Future<Output = Result<()>> + '_;
}

pub async fn missing_paths(paths: &[StorePath]) -> Result<Vec<StorePath>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    let mut missing = BTreeSet::new();
    for chunk in paths.chunks(PATH_ARG_CHUNK_SIZE) {
        let mut args = Vec::with_capacity(chunk.len() + 2);
        args.push("--check-validity");
        args.push("--print-invalid");
        args.extend(chunk.iter().map(StorePath::as_str));

        let output = command_output("nix-store", &args).await?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!("nix-store failed: {}", stderr.trim());
        }

        for path in String::from_utf8(output.stdout)
            .context("command output was not UTF-8")?
            .lines()
            .filter_map(non_empty_line)
        {
            missing.insert(StorePath::new(path)?.as_str().to_string());
        }
    }

    Ok(paths
        .iter()
        .filter(|path| missing.contains(path.as_str()))
        .cloned()
        .collect())
}

pub async fn realise<S>(
    path: &StorePath,
    output_mode: OutputMode,
    log_sink: &mut S,
) -> Result<RealiseResult>
where
    S: LogSink + ?Sized,
{
    let mut child = Command::new("nix-store")
        .args(realise_args(output_mode))
        .arg(path.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("run nix-store --realise")?;

    let stdout = child.stdout.take().context("nix-store stdout not piped")?;
    let stderr = child.stderr.take().context("nix-store stderr not piped")?;
    stream_child_lines(stdout, stderr, log_sink).await?;

    let status = child.wait().await.context("wait for nix-store --realise")?;
    let success = status.success();
    let output_paths = if success {
        query_outputs(path).await?
    } else {
        Vec::new()
    };

    Ok(RealiseResult {
        success,
        output_paths,
    })
}

pub async fn export_paths<W>(paths: &[StorePath], writer: &mut W) -> Result<()>
where
    W: AsyncWrite + Unpin + ?Sized,
{
    if paths.is_empty() {
        return Ok(());
    }

    let mut child = Command::new("nix-store")
        .arg("--export")
        .args(paths.iter().map(StorePath::as_str))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("run nix-store --export")?;

    let mut stdout = child.stdout.take().context("nix-store stdout not piped")?;
    let copy_result = tokio::io::copy(&mut stdout, writer).await;
    drop(stdout);

    let output = child
        .wait_with_output()
        .await
        .context("wait for nix-store --export")?;
    copy_result.context("stream nix-store export")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nix-store --export failed: {}", stderr.trim());
    }

    Ok(())
}

pub async fn output_closure(paths: &[StorePath]) -> Result<Vec<StorePath>> {
    query_closure(paths).await
}

pub async fn import_unsigned_export_stream<R>(reader: &mut R, max_bytes: Option<u64>) -> Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let mut child = Command::new("nix-store")
        .args(["--option", "require-sigs", "false", "--import"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .context("run nix-store --import")?;

    let mut stdin = child.stdin.take().context("nix-store stdin not piped")?;
    let copy_result = match max_bytes {
        Some(max_bytes) => {
            let mut limited = reader.take(max_bytes.saturating_add(1));
            tokio::io::copy(&mut limited, &mut stdin).await
        }
        None => tokio::io::copy(reader, &mut stdin).await,
    };

    let copied = match copy_result {
        Ok(copied) => copied,
        Err(err) => {
            drop(stdin);
            let output = child
                .wait_with_output()
                .await
                .context("wait for failed nix-store --import")?;
            let stderr = String::from_utf8_lossy(&output.stderr);
            bail!(
                "stream nix-store import: {err}; nix-store stderr: {}",
                stderr.trim()
            );
        }
    };

    if max_bytes.is_some_and(|max_bytes| copied > max_bytes) {
        drop(stdin);
        let _ = child.kill().await;
        bail!("upload exceeded max bytes: {copied}");
    }

    drop(stdin);
    let output = child
        .wait_with_output()
        .await
        .context("wait for nix-store --import")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("nix-store --import failed: {}", stderr.trim());
    }

    Ok(copied)
}

pub async fn copy_to_signed_binary_cache(
    paths: &[StorePath],
    cache_dir: &Path,
    secret_key: &Path,
) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }

    let cache_url = file_cache_url(cache_dir, Some(secret_key))?;
    for chunk in paths.chunks(PATH_ARG_CHUNK_SIZE) {
        let mut args = vec!["copy".to_string(), "--to".to_string(), cache_url.clone()];
        args.extend(chunk.iter().map(|path| path.as_str().to_string()));
        run_nix_command(args, "nix copy to signed binary cache").await?;
    }
    Ok(())
}

pub async fn copy_from_signed_binary_cache(
    cache_url: &str,
    public_key: &str,
    paths: &[StorePath],
) -> Result<()> {
    if paths.is_empty() {
        return Ok(());
    }

    let public_key = public_key.trim();
    if public_key.is_empty() {
        bail!("trusted public key is empty");
    }

    for chunk in paths.chunks(PATH_ARG_CHUNK_SIZE) {
        let mut args = vec![
            "copy".to_string(),
            "--from".to_string(),
            cache_url.to_string(),
            "--option".to_string(),
            "require-sigs".to_string(),
            "true".to_string(),
            "--option".to_string(),
            "trusted-public-keys".to_string(),
            public_key.to_string(),
        ];
        args.extend(chunk.iter().map(|path| path.as_str().to_string()));
        if let Err(err) = run_nix_command(args, "nix copy from signed binary cache").await {
            let message = err.to_string();
            if is_signature_or_trust_error(&message) {
                bail!(
                    "signed cache/public key import failed; Nix rejected cache signatures/trust: {message}"
                );
            }
            return Err(err);
        }
    }
    Ok(())
}

fn file_cache_url(cache_dir: &Path, secret_key: Option<&Path>) -> Result<String> {
    let cache_dir = path_to_str(cache_dir)?;
    let mut url = format!("file://{cache_dir}");
    if let Some(secret_key) = secret_key {
        url.push_str("?secret-key=");
        url.push_str(path_to_str(secret_key)?);
    }
    Ok(url)
}

fn path_to_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not UTF-8: {}", path.display()))
}

async fn run_nix_command(args: Vec<String>, context: &str) -> Result<()> {
    let output = Command::new("nix")
        .args(&args)
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("run {context}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr = stderr.trim();
        if stderr.is_empty() {
            bail!("{context} failed with {}", output.status);
        }
        bail!("{context} failed: {stderr}");
    }

    Ok(())
}

async fn query_closure(paths: &[StorePath]) -> Result<Vec<StorePath>> {
    if paths.is_empty() {
        return Ok(Vec::new());
    }

    let mut args = Vec::with_capacity(paths.len() + 1);
    args.push("-qR");
    args.extend(paths.iter().map(StorePath::as_str));

    let output = run_command("nix-store", &args).await?;
    let mut seen = std::collections::BTreeSet::new();
    let mut closure = Vec::new();
    for line in output.lines().filter_map(non_empty_line) {
        let path = StorePath::new(line)?;
        if seen.insert(path.as_str().to_string()) {
            closure.push(path);
        }
    }
    Ok(closure)
}

async fn query_outputs(path: &StorePath) -> Result<Vec<StorePath>> {
    let output = run_command("nix-store", &["-q", "--outputs", path.as_str()]).await?;
    output
        .lines()
        .filter_map(non_empty_line)
        .map(StorePath::new)
        .collect()
}

async fn stream_child_lines<S, O, E>(stdout: O, stderr: E, log_sink: &mut S) -> Result<()>
where
    S: LogSink + ?Sized,
    O: AsyncRead + Unpin,
    E: AsyncRead + Unpin,
{
    let mut stdout_lines = BufReader::new(stdout).lines();
    let mut stderr_lines = BufReader::new(stderr).lines();
    let mut stdout_done = false;
    let mut stderr_done = false;

    while !stdout_done || !stderr_done {
        tokio::select! {
            line = stdout_lines.next_line(), if !stdout_done => {
                match line.context("read nix-store stdout")? {
                    Some(line) => log_sink.log_line(line).await?,
                    None => stdout_done = true,
                }
            }
            line = stderr_lines.next_line(), if !stderr_done => {
                match line.context("read nix-store stderr")? {
                    Some(line) => log_sink.log_line(line).await?,
                    None => stderr_done = true,
                }
            }
        }
    }

    Ok(())
}

fn realise_args(output_mode: OutputMode) -> [&'static str; 4] {
    match output_mode {
        OutputMode::Nom => ["--realise", "--log-format", "internal-json", "-v"],
        OutputMode::Plain => ["--realise", "--log-format", "raw", "-v"],
    }
}

fn validate_store_path(path: &str) -> Result<()> {
    let Some(rest) = path.strip_prefix(STORE_PREFIX) else {
        bail!("not a Nix store path: {path}");
    };

    let Some((hash, name)) = rest.split_once('-') else {
        bail!("invalid Nix store path: {path}");
    };

    if hash.len() != HASH_LEN || !hash.chars().all(|c| NIX_BASE32.contains(c)) {
        bail!("invalid Nix store path hash: {path}");
    }

    if name.is_empty() || !name.chars().all(valid_store_name_char) {
        bail!("invalid Nix store path name: {path}");
    }

    Ok(())
}

fn valid_store_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.' | '_' | '?' | '=')
}

fn non_empty_line(line: &str) -> Option<String> {
    let line = line.trim();
    (!line.is_empty()).then(|| line.to_string())
}

fn is_signature_or_trust_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("signature")
        || message.contains("trusted public")
        || message.contains("trusted-public-keys")
        || message.contains("trusted key")
        || message.contains("public key")
}

async fn run_command(program: &str, args: &[&str]) -> Result<String> {
    let output = command_output(program, args).await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("{program} failed: {}", stderr.trim());
    }

    String::from_utf8(output.stdout).context("command output was not UTF-8")
}

async fn command_output(program: &str, args: &[&str]) -> Result<Output> {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .with_context(|| format!("run {program}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_store_paths() {
        let path =
            StorePath::new("/nix/store/00000000000000000000000000000000-foo+bar_1.0?x=y").unwrap();
        assert_eq!(
            path.as_str(),
            "/nix/store/00000000000000000000000000000000-foo+bar_1.0?x=y"
        );
    }

    #[test]
    fn rejects_invalid_store_paths() {
        for path in [
            "/tmp/abc",
            "/nix/store/abc-source",
            "/nix/store/00000000000000000000000000000000",
            "/nix/store/00000000000000000000000000000000-",
            "/nix/store/00000000000000000000000000000000-foo/bar",
            "/nix/store/00000000000000000000000000000000-foo bar",
        ] {
            assert!(StorePath::new(path).is_err(), "accepted {path}");
        }
    }

    #[test]
    fn parses_requested_build_outputs() {
        let output = r#"[{"drvPath":"/nix/store/00000000000000000000000000000000-git.drv","outputs":{"debug":"/nix/store/11111111111111111111111111111111-git-debug","doc":"/nix/store/22222222222222222222222222222222-git-doc","out":"/nix/store/33333333333333333333333333333333-git"}}]"#;
        let paths = parse_build_plan_outputs(output).unwrap();
        assert_eq!(
            paths.iter().map(StorePath::as_str).collect::<Vec<_>>(),
            [
                "/nix/store/11111111111111111111111111111111-git-debug",
                "/nix/store/22222222222222222222222222222222-git-doc",
                "/nix/store/33333333333333333333333333333333-git",
            ]
        );
    }

    #[test]
    fn detects_signature_or_trust_errors() {
        assert!(is_signature_or_trust_error(
            "cannot add path because it lacks a signature by a trusted key"
        ));
        assert!(is_signature_or_trust_error(
            "unknown public key in trusted-public-keys"
        ));
        assert!(!is_signature_or_trust_error("HTTP error 404"));
    }
}
