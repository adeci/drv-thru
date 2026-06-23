use anyhow::{Context, Result};
use iroh::EndpointId;

use crate::config::{
    DEFAULT_MAX_BUILD_TIME, DEFAULT_MAX_UPLOAD_BYTES, ServerConfig, TrustedClient,
};

#[derive(Clone)]
pub struct AccessPolicy {
    trusted_clients: Vec<TrustedEndpoint>,
}

#[derive(Clone)]
struct TrustedEndpoint {
    name: Option<String>,
    endpoint_id: EndpointId,
    policy: TrustedClient,
}

pub struct AuthorizedClient {
    pub name: Option<String>,
    pub policy: TrustedClient,
}

impl AccessPolicy {
    pub fn from_config(config: &ServerConfig) -> Result<Self> {
        let mut trusted_clients = Vec::with_capacity(config.trusted_clients.len());

        for (name, client) in &config.trusted_clients {
            let endpoint_id = client
                .public_key
                .parse::<EndpointId>()
                .with_context(|| format!("parse public_key for trusted client {name}"))?;
            trusted_clients.push(TrustedEndpoint {
                name: Some(name.clone()),
                endpoint_id,
                policy: client.clone(),
            });
        }

        Ok(Self { trusted_clients })
    }

    pub fn from_endpoint_ids(endpoint_ids: Vec<EndpointId>) -> Self {
        let trusted_clients = endpoint_ids
            .into_iter()
            .map(|endpoint_id| TrustedEndpoint {
                name: None,
                endpoint_id,
                policy: TrustedClient {
                    public_key: endpoint_id.to_string(),
                    max_build_time: Some(DEFAULT_MAX_BUILD_TIME.to_string()),
                    max_upload_bytes: Some(DEFAULT_MAX_UPLOAD_BYTES.to_string()),
                },
            })
            .collect();
        Self { trusted_clients }
    }

    pub fn authorize(&self, remote: &EndpointId) -> Option<AuthorizedClient> {
        self.trusted_clients
            .iter()
            .find(|client| &client.endpoint_id == remote)
            .map(|client| AuthorizedClient {
                name: client.name.clone(),
                policy: client.policy.clone(),
            })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, path::PathBuf};

    use iroh::SecretKey;

    use super::*;

    #[test]
    fn authorizes_named_client() {
        let endpoint_id = SecretKey::generate().public();
        let config = config_with_client("laptop", endpoint_id, Some("30m".to_string()));
        let policy = AccessPolicy::from_config(&config).unwrap();

        let client = policy.authorize(&endpoint_id).unwrap();
        assert_eq!(client.name.as_deref(), Some("laptop"));
        assert_eq!(client.policy.max_build_time.as_deref(), Some("30m"));
    }

    #[test]
    fn rejects_unknown_client() {
        let trusted = SecretKey::generate().public();
        let unknown = SecretKey::generate().public();
        let config = config_with_client("laptop", trusted, None);
        let policy = AccessPolicy::from_config(&config).unwrap();

        assert!(policy.authorize(&unknown).is_none());
    }

    fn config_with_client(
        name: &str,
        endpoint_id: EndpointId,
        max_build_time: Option<String>,
    ) -> ServerConfig {
        let mut trusted_clients = BTreeMap::new();
        trusted_clients.insert(
            name.to_string(),
            TrustedClient {
                public_key: endpoint_id.to_string(),
                max_build_time,
                max_upload_bytes: None,
            },
        );

        ServerConfig {
            data_dir: PathBuf::from("/tmp/drv-thru"),
            secret_key_file: None,
            max_concurrent_builds: 1,
            trusted_clients,
        }
    }
}
