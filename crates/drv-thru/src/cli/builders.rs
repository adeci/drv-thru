use std::{collections::BTreeMap, io::ErrorKind, path::PathBuf};

use anyhow::{Context, Result, bail};
use iroh::{EndpointId, RelayUrl};
use serde::Deserialize;

use crate::client::BuildAuth;

const SYSTEM_BUILDERS_CONFIG_PATH: &str = "/etc/drv-thru/builders.json";
const BUILDERS_CONFIG_ENV: &str = "DRV_THRU_BUILDERS_CONFIG";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildersConfig {
    builders: BTreeMap<String, SavedBuilder>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedBuilder {
    #[serde(default)]
    endpoint_id: Option<String>,
    #[serde(default)]
    endpoint_id_file: Option<PathBuf>,
    #[serde(default)]
    relay_url: Option<String>,
}

pub(super) fn load(name: &str) -> Result<BuildAuth> {
    let config = load_config()?;
    builder_auth(name, &config)
}

fn load_config() -> Result<BuildersConfig> {
    let env_config = std::env::var_os(BUILDERS_CONFIG_ENV).map(PathBuf::from);
    let paths = config_paths(env_config.as_ref());
    let mut builders = BTreeMap::new();
    let mut loaded = Vec::new();

    for path in &paths {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let config =
                    parse_config(&text).with_context(|| format!("parse {}", path.display()))?;
                builders.extend(config.builders);
                loaded.push(path.display().to_string());
            }
            Err(err) if err.kind() == ErrorKind::NotFound && env_config.is_none() => {}
            Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
        }
    }

    if loaded.is_empty() {
        let checked = paths
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ");
        bail!(
            "builder config not found; checked {checked}; configure services.drv-thru.client.builders.<name>, create ~/.config/drv-thru/builders.json, or pass --server"
        );
    }

    Ok(BuildersConfig { builders })
}

fn config_paths(env_config: Option<&PathBuf>) -> Vec<PathBuf> {
    if let Some(path) = env_config {
        return vec![path.clone()];
    }

    let mut paths = vec![PathBuf::from(SYSTEM_BUILDERS_CONFIG_PATH)];
    if let Some(path) = user_config_path() {
        paths.push(path);
    }
    paths
}

fn user_config_path() -> Option<PathBuf> {
    if let Some(config_home) = std::env::var_os("XDG_CONFIG_HOME") {
        return Some(PathBuf::from(config_home).join("drv-thru/builders.json"));
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .map(|home| home.join(".config/drv-thru/builders.json"))
}

fn parse_config(text: &str) -> Result<BuildersConfig> {
    serde_json::from_str(text).context("decode builder config")
}

fn builder_auth(name: &str, config: &BuildersConfig) -> Result<BuildAuth> {
    let builder = config.builders.get(name).with_context(|| {
        let known = config
            .builders
            .keys()
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        if known.is_empty() {
            format!("builder '{name}' was not found; no builders are configured")
        } else {
            format!("builder '{name}' was not found; configured builders: {known}")
        }
    })?;

    let server_id = endpoint_id(name, builder)?;
    let relay_url = builder
        .relay_url
        .as_deref()
        .map(str::parse::<RelayUrl>)
        .transpose()
        .with_context(|| format!("parse relay_url for builder {name}"))?;

    Ok(BuildAuth::TrustedClient {
        server_id,
        relay_url,
    })
}

fn endpoint_id(name: &str, builder: &SavedBuilder) -> Result<EndpointId> {
    let endpoint_id = match (&builder.endpoint_id, &builder.endpoint_id_file) {
        (Some(_), Some(_)) => {
            bail!("builder {name} must set only one of endpoint_id or endpoint_id_file")
        }
        (Some(endpoint_id), None) => endpoint_id.clone(),
        (None, Some(path)) => std::fs::read_to_string(path)
            .with_context(|| {
                format!(
                    "read endpoint_id_file for builder {name}: {}",
                    path.display()
                )
            })?
            .trim()
            .to_string(),
        (None, None) => bail!("builder {name} must set endpoint_id or endpoint_id_file"),
    };

    if endpoint_id.is_empty() {
        bail!("endpoint id for builder {name} is empty");
    }
    endpoint_id
        .parse::<EndpointId>()
        .with_context(|| format!("parse endpoint id for builder {name}"))
}

#[cfg(test)]
mod tests {
    use std::{fs, path::PathBuf};

    use iroh::SecretKey;

    use super::{builder_auth, config_paths, parse_config};
    use crate::client::BuildAuth;

    #[test]
    fn resolves_named_builder_from_config() {
        let server_id = SecretKey::generate().public();
        let config = parse_config(&format!(
            r#"{{"builders":{{"leviathan":{{"endpoint_id":"{server_id}","relay_url":"https://use1-1.relay.n0.iroh.link./"}}}}}}"#
        ))
        .unwrap();

        let BuildAuth::TrustedClient {
            server_id: resolved,
            relay_url,
        } = builder_auth("leviathan", &config).unwrap()
        else {
            panic!("expected trusted client auth");
        };

        assert_eq!(resolved, server_id);
        assert_eq!(
            relay_url.unwrap().to_string(),
            "https://use1-1.relay.n0.iroh.link./"
        );
    }

    #[test]
    fn resolves_named_builder_endpoint_from_file() {
        let server_id = SecretKey::generate().public();
        let path = temp_endpoint_file("drv-thru-builder-endpoint", &server_id.to_string());
        let config = parse_config(&format!(
            r#"{{"builders":{{"leviathan":{{"endpoint_id_file":"{}"}}}}}}"#,
            path.display()
        ))
        .unwrap();

        let BuildAuth::TrustedClient {
            server_id: resolved,
            relay_url,
        } = builder_auth("leviathan", &config).unwrap()
        else {
            panic!("expected trusted client auth");
        };

        assert_eq!(resolved, server_id);
        assert_eq!(relay_url, None);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_unknown_named_builder() {
        let config = parse_config(r#"{"builders":{}}"#).unwrap();
        let Err(err) = builder_auth("leviathan", &config) else {
            panic!("accepted unknown builder");
        };
        assert!(err.to_string().contains("was not found"));
    }

    #[test]
    fn user_builder_config_overrides_system_config() {
        let env_config = None;
        let paths = config_paths(env_config);

        assert_eq!(paths[0], PathBuf::from("/etc/drv-thru/builders.json"));
        assert!(paths.last().unwrap().ends_with("drv-thru/builders.json"));
    }

    fn temp_endpoint_file(name: &str, text: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
        fs::write(&path, text).unwrap();
        path
    }
}
