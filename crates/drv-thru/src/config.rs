use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

pub const DEFAULT_MAX_BUILD_TIME: &str = "30m";
pub const DEFAULT_MAX_UPLOAD_BYTES: &str = "20G";
pub const DEFAULT_MAX_CONCURRENT_BUILDS: usize = 1;
pub const DEFAULT_RECENT_BUILDS_LIMIT: usize = 20;
pub const MAX_AUTO_CACHE_FILLS: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub data_dir: PathBuf,
    #[serde(default)]
    pub secret_key_file: Option<PathBuf>,
    #[serde(default = "default_max_concurrent_builds")]
    pub max_concurrent_builds: usize,
    #[serde(default)]
    pub output_cache_max_parallel_fills: Option<usize>,
    #[serde(default = "default_recent_builds_limit")]
    pub recent_builds_limit: usize,
    #[serde(default)]
    pub trusted_clients: BTreeMap<String, TrustedClient>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedClient {
    pub public_key: String,
    #[serde(default = "default_max_build_time")]
    pub max_build_time: Option<String>,
    #[serde(default = "default_max_upload_bytes")]
    pub max_upload_bytes: Option<String>,
}

#[allow(clippy::unnecessary_wraps)]
fn default_max_build_time() -> Option<String> {
    Some(DEFAULT_MAX_BUILD_TIME.to_string())
}

#[allow(clippy::unnecessary_wraps)]
fn default_max_upload_bytes() -> Option<String> {
    Some(DEFAULT_MAX_UPLOAD_BYTES.to_string())
}

fn default_max_concurrent_builds() -> usize {
    DEFAULT_MAX_CONCURRENT_BUILDS
}

fn default_recent_builds_limit() -> usize {
    DEFAULT_RECENT_BUILDS_LIMIT
}

pub fn load_server_config(path: impl AsRef<Path>) -> Result<ServerConfig> {
    let path = path.as_ref();
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let config: ServerConfig =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    if config.max_concurrent_builds == 0 {
        bail!("max_concurrent_builds must be at least 1");
    }
    if config.output_cache_max_parallel_fills == Some(0) {
        bail!("output_cache_max_parallel_fills must be at least 1");
    }
    if config.recent_builds_limit == 0 {
        bail!("recent_builds_limit must be at least 1");
    }
    Ok(config)
}

pub fn parse_byte_count(value: &str) -> Result<u64> {
    let (number, suffix) = parse_number_and_suffix(value)?;
    let multiplier = match suffix.as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024_u64.pow(4),
        _ => bail!("unknown byte count suffix: {value}"),
    };

    number
        .checked_mul(multiplier)
        .with_context(|| format!("byte count overflow: {value}"))
}

pub fn parse_duration(value: &str) -> Result<Duration> {
    let (number, suffix) = parse_number_and_suffix(value)?;
    let seconds = match suffix.as_str() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => number,
        "m" | "min" | "mins" | "minute" | "minutes" => number
            .checked_mul(60)
            .with_context(|| format!("duration overflow: {value}"))?,
        "h" | "hr" | "hrs" | "hour" | "hours" => number
            .checked_mul(60 * 60)
            .with_context(|| format!("duration overflow: {value}"))?,
        _ => bail!("unknown duration suffix: {value}"),
    };

    Ok(Duration::from_secs(seconds))
}

fn parse_number_and_suffix(value: &str) -> Result<(u64, String)> {
    let value = value.trim();
    if value.is_empty() {
        bail!("empty value");
    }

    let split_at = value
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(value.len());
    let (digits, suffix) = value.split_at(split_at);
    if digits.is_empty() {
        bail!("invalid number: {value}");
    }

    let number = digits
        .parse::<u64>()
        .with_context(|| format!("parse number: {value}"))?;
    Ok((number, suffix.trim().to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_defaults_empty_trusted_clients() {
        let config: ServerConfig = serde_json::from_str(r#"{"data_dir":"/tmp/drv-thru"}"#).unwrap();

        assert_eq!(config.data_dir, PathBuf::from("/tmp/drv-thru"));
        assert!(config.secret_key_file.is_none());
        assert_eq!(config.max_concurrent_builds, DEFAULT_MAX_CONCURRENT_BUILDS);
        assert_eq!(config.output_cache_max_parallel_fills, None);
        assert_eq!(config.recent_builds_limit, DEFAULT_RECENT_BUILDS_LIMIT);
        assert!(config.trusted_clients.is_empty());
    }

    #[test]
    fn trusted_client_defaults_optional_fields() {
        let config: ServerConfig = serde_json::from_str(
            r#"{
                "data_dir":"/tmp/drv-thru",
                "trusted_clients":{
                    "laptop":{"public_key":"abc"}
                }
            }"#,
        )
        .unwrap();

        let client = config.trusted_clients.get("laptop").unwrap();
        assert_eq!(client.public_key, "abc");
        assert_eq!(
            client.max_build_time.as_deref(),
            Some(DEFAULT_MAX_BUILD_TIME)
        );
        assert_eq!(
            client.max_upload_bytes.as_deref(),
            Some(DEFAULT_MAX_UPLOAD_BYTES)
        );
    }

    #[test]
    fn server_config_accepts_max_concurrent_builds() {
        let config: ServerConfig =
            serde_json::from_str(r#"{"data_dir":"/tmp/drv-thru","max_concurrent_builds":2}"#)
                .unwrap();

        assert_eq!(config.max_concurrent_builds, 2);
    }

    #[test]
    fn server_config_accepts_output_cache_max_parallel_fills() {
        let config: ServerConfig = serde_json::from_str(
            r#"{"data_dir":"/tmp/drv-thru","output_cache_max_parallel_fills":8}"#,
        )
        .unwrap();

        assert_eq!(config.output_cache_max_parallel_fills, Some(8));
    }

    #[test]
    fn load_server_config_rejects_zero_max_concurrent_builds() {
        let path = std::env::temp_dir().join(format!(
            "drv-thru-zero-max-concurrent-builds-{}.json",
            std::process::id()
        ));
        fs::write(
            &path,
            r#"{"data_dir":"/tmp/drv-thru","max_concurrent_builds":0}"#,
        )
        .unwrap();

        assert!(load_server_config(&path).is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn server_config_accepts_recent_builds_limit() {
        let config: ServerConfig =
            serde_json::from_str(r#"{"data_dir":"/tmp/drv-thru","recent_builds_limit":5}"#)
                .unwrap();

        assert_eq!(config.recent_builds_limit, 5);
    }

    #[test]
    fn load_server_config_rejects_zero_output_cache_max_parallel_fills() {
        let path = std::env::temp_dir().join(format!(
            "drv-thru-zero-output-cache-max-parallel-fills-{}.json",
            std::process::id()
        ));
        fs::write(
            &path,
            r#"{"data_dir":"/tmp/drv-thru","output_cache_max_parallel_fills":0}"#,
        )
        .unwrap();

        assert!(load_server_config(&path).is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn load_server_config_rejects_zero_recent_builds_limit() {
        let path = std::env::temp_dir().join(format!(
            "drv-thru-zero-recent-builds-limit-{}.json",
            std::process::id()
        ));
        fs::write(
            &path,
            r#"{"data_dir":"/tmp/drv-thru","recent_builds_limit":0}"#,
        )
        .unwrap();

        assert!(load_server_config(&path).is_err());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn parses_byte_counts() {
        assert_eq!(parse_byte_count("1").unwrap(), 1);
        assert_eq!(parse_byte_count("2K").unwrap(), 2 * 1024);
        assert_eq!(parse_byte_count("3M").unwrap(), 3 * 1024 * 1024);
        assert_eq!(parse_byte_count("4G").unwrap(), 4 * 1024 * 1024 * 1024);
        assert!(parse_byte_count("1 nope").is_err());
    }

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("1").unwrap(), Duration::from_secs(1));
        assert_eq!(parse_duration("2m").unwrap(), Duration::from_mins(2));
        assert_eq!(parse_duration("3h").unwrap(), Duration::from_hours(3));
        assert!(parse_duration("1d").is_err());
    }
}
