//! Copy-paste build tickets and their server-side state.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, Formatter},
    fs,
    io::ErrorKind,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use iroh::{EndpointAddr, EndpointId, RelayUrl, SecretKey};
use iroh_tickets::{ParseError, Ticket};
use serde::{Deserialize, Serialize};

use crate::{process_lock, state::json};

const TICKETS_FILE: &str = "tickets.json";
const SERVER_ADDR_FILE: &str = "server-addr.json";

#[derive(Clone)]
pub struct BuildTicket {
    addr: EndpointAddr,
    secret: [u8; 32],
}

#[derive(Serialize, Deserialize)]
enum TicketWireFormat {
    Variant0(Variant0BuildTicket),
}

#[derive(Serialize, Deserialize)]
struct Variant0BuildTicket {
    node: Variant0NodeAddr,
    secret: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct Variant0NodeAddr {
    endpoint_id: EndpointId,
    relay_url: Option<RelayUrl>,
    direct_addrs: BTreeSet<SocketAddr>,
}

impl Ticket for BuildTicket {
    const KIND: &'static str = "drvthru";

    fn encode_bytes(&self) -> Vec<u8> {
        let data = TicketWireFormat::Variant0(Variant0BuildTicket {
            node: Variant0NodeAddr {
                endpoint_id: self.addr.id,
                relay_url: self.addr.relay_urls().next().cloned(),
                direct_addrs: self.addr.ip_addrs().copied().collect(),
            },
            secret: self.secret,
        });
        postcard::to_stdvec(&data).expect("postcard serialization failed")
    }

    fn decode_bytes(bytes: &[u8]) -> std::result::Result<Self, ParseError> {
        let TicketWireFormat::Variant0(data) = postcard::from_bytes(bytes)?;
        let mut addr = EndpointAddr::new(data.node.endpoint_id);
        if let Some(relay_url) = data.node.relay_url {
            addr = addr.with_relay_url(relay_url);
        }
        for direct_addr in data.node.direct_addrs {
            addr = addr.with_ip_addr(direct_addr);
        }
        Ok(Self {
            addr,
            secret: data.secret,
        })
    }
}

impl Display for BuildTicket {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&Ticket::encode_string(self))
    }
}

impl FromStr for BuildTicket {
    type Err = ParseError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        Ticket::decode_string(value)
    }
}

impl BuildTicket {
    fn generate(addr: &EndpointAddr) -> Self {
        Self {
            addr: compact_ticket_addr(addr),
            secret: SecretKey::generate().to_bytes(),
        }
    }

    pub fn addr(&self) -> &EndpointAddr {
        &self.addr
    }

    pub fn secret(&self) -> [u8; 32] {
        self.secret
    }

    pub fn id(&self) -> String {
        ticket_id(&self.secret)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketRecord {
    pub encoded_ticket: String,
    pub created_at_unix: u64,
    pub name: Option<String>,
    pub expires_at_unix: u64,
    pub uses_remaining: Option<u64>,
    pub max_build_time: String,
    pub max_upload_bytes: String,
    #[serde(default)]
    pub bound_client: Option<String>,
    #[serde(default)]
    pub revoked: bool,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TicketState {
    #[serde(default)]
    pub tickets: BTreeMap<String, TicketRecord>,
}

pub struct CreateTicket {
    pub name: Option<String>,
    pub bound_client: Option<String>,
    pub expires_after: Duration,
    pub uses_remaining: Option<u64>,
    pub max_build_time: String,
    pub max_upload_bytes: String,
}

#[derive(Clone)]
pub struct TicketStore {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl TicketStore {
    pub fn new(data_dir: impl AsRef<Path>) -> Self {
        Self {
            path: data_dir.as_ref().join(TICKETS_FILE),
            lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn load(&self) -> Result<TicketState> {
        let _guard = self.lock.lock().expect("ticket store lock poisoned");
        let _file_lock = self.lock_file()?;
        self.load_unlocked()
    }

    pub fn create(&self, server_addr: &EndpointAddr, options: CreateTicket) -> Result<BuildTicket> {
        let _guard = self.lock.lock().expect("ticket store lock poisoned");
        let _file_lock = self.lock_file()?;
        let mut state = self.load_unlocked()?;
        let now = now_unix_secs()?;
        let expires_at = now
            .checked_add(options.expires_after.as_secs())
            .context("ticket expiry overflow")?;
        let name = match options.name {
            Some(name) if name.trim().is_empty() => bail!("ticket name cannot be empty"),
            Some(name) => Some(name),
            None => Some(default_ticket_name(now)),
        };
        if let Some(bound_client) = &options.bound_client {
            bound_client
                .parse::<EndpointId>()
                .with_context(|| format!("parse bound client endpoint id: {bound_client}"))?;
        }

        let ticket = BuildTicket::generate(server_addr);
        let id = ticket.id();
        let encoded_ticket = ticket.to_string();
        let old = state.tickets.insert(
            id.clone(),
            TicketRecord {
                encoded_ticket,
                created_at_unix: now,
                name,
                expires_at_unix: expires_at,
                uses_remaining: options.uses_remaining,
                max_build_time: options.max_build_time,
                max_upload_bytes: options.max_upload_bytes,
                bound_client: options.bound_client,
                revoked: false,
            },
        );
        if old.is_some() {
            bail!("ticket id collision: {id}");
        }

        self.write_unlocked(&state)?;
        Ok(ticket)
    }

    pub fn records(&self) -> Result<Vec<(String, TicketRecord)>> {
        let mut records = self.load()?.tickets.into_iter().collect::<Vec<_>>();
        records.sort_by(|(left_id, left), (right_id, right)| {
            left.created_at_unix
                .cmp(&right.created_at_unix)
                .then_with(|| left_id.cmp(right_id))
        });
        Ok(records)
    }

    pub fn record(&self, id: &str) -> Result<Option<TicketRecord>> {
        Ok(self.load()?.tickets.get(id).cloned())
    }

    pub fn revoke(&self, id: &str) -> Result<TicketRecord> {
        let _guard = self.lock.lock().expect("ticket store lock poisoned");
        let _file_lock = self.lock_file()?;
        let mut state = self.load_unlocked()?;
        let record = state
            .tickets
            .get_mut(id)
            .with_context(|| format!("ticket not found: {id}"))?;
        record.revoked = true;
        let revoked = record.clone();
        self.write_unlocked(&state)?;
        Ok(revoked)
    }

    pub fn check(&self, secret: &[u8; 32], remote: &EndpointId) -> Result<TicketRecord> {
        let _guard = self.lock.lock().expect("ticket store lock poisoned");
        let _file_lock = self.lock_file()?;
        let state = self.load_unlocked()?;
        let id = ticket_id(secret);
        let record = state
            .tickets
            .get(&id)
            .with_context(|| format!("ticket not found: {id}"))?;
        validate_ticket_record(&id, record, remote)?;
        Ok(record.clone())
    }

    pub fn redeem(&self, secret: &[u8; 32], remote: &EndpointId) -> Result<TicketRecord> {
        let _guard = self.lock.lock().expect("ticket store lock poisoned");
        let _file_lock = self.lock_file()?;
        let mut state = self.load_unlocked()?;
        let id = ticket_id(secret);
        let record = state
            .tickets
            .get_mut(&id)
            .with_context(|| format!("ticket not found: {id}"))?;
        validate_ticket_record(&id, record, remote)?;

        match &mut record.uses_remaining {
            Some(uses_remaining) => {
                *uses_remaining -= 1;
                let redeemed = record.clone();
                self.write_unlocked(&state)?;
                Ok(redeemed)
            }
            None => Ok(record.clone()),
        }
    }

    fn lock_file(&self) -> Result<TicketFileLock> {
        let lock_path = ticket_store_lock_path(&self.path)?;
        loop {
            match create_ticket_store_lock(&lock_path) {
                Ok(()) => return Ok(TicketFileLock { path: lock_path }),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    remove_stale_ticket_store_lock(&lock_path);
                    thread::sleep(Duration::from_millis(50));
                }
                Err(err) => {
                    return Err(err).with_context(|| format!("lock {}", self.path.display()));
                }
            }
        }
    }

    fn load_unlocked(&self) -> Result<TicketState> {
        let text = match fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(TicketState::default()),
            Err(err) => return Err(err).with_context(|| format!("read {}", self.path.display())),
        };
        serde_json::from_str(&text).with_context(|| format!("parse {}", self.path.display()))
    }

    fn write_unlocked(&self, state: &TicketState) -> Result<()> {
        json::write_atomic_with_mode(&self.path, state, "encode JSON", 0o660)
    }
}

struct TicketFileLock {
    path: PathBuf,
}

impl Drop for TicketFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn validate_ticket_record(id: &str, record: &TicketRecord, remote: &EndpointId) -> Result<()> {
    if record.revoked {
        bail!("ticket revoked");
    }
    if now_unix_secs()? >= record.expires_at_unix {
        bail!("ticket expired");
    }
    if let Some(bound_client) = &record.bound_client {
        let bound_client = bound_client
            .parse::<EndpointId>()
            .with_context(|| format!("parse bound client for ticket {id}"))?;
        if &bound_client != remote {
            bail!("ticket bound to a different client");
        }
    }
    if matches!(record.uses_remaining, Some(0)) {
        bail!("ticket has no uses remaining");
    }
    Ok(())
}

fn ticket_store_lock_path(path: &Path) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .with_context(|| format!("path has no UTF-8 file name: {}", path.display()))?;
    Ok(path.with_file_name(format!(".{file_name}.lock")))
}

fn create_ticket_store_lock(path: &Path) -> std::io::Result<()> {
    fs::create_dir(path)?;
    let write_owner = (|| -> std::io::Result<()> {
        fs::write(path.join("pid"), std::process::id().to_string())?;
        fs::write(path.join("owner"), process_lock::current_owner_text())
    })();
    if let Err(err) = write_owner {
        let _ = fs::remove_dir_all(path);
        return Err(err);
    }
    Ok(())
}

fn remove_stale_ticket_store_lock(path: &Path) {
    let owner_text = fs::read_to_string(path.join("owner"))
        .or_else(|_| fs::read_to_string(path.join("pid")))
        .unwrap_or_default();
    if process_lock::owner_is_live(&owner_text) {
        return;
    }

    let _ = fs::remove_dir_all(path);
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerAddrFile {
    endpoint_id: String,
    relay_url: Option<String>,
    #[serde(default)]
    direct_addrs: Vec<String>,
}

impl ServerAddrFile {
    fn from_addr(addr: &EndpointAddr) -> Self {
        Self {
            endpoint_id: addr.id.to_string(),
            relay_url: addr.relay_urls().next().map(ToString::to_string),
            direct_addrs: addr.ip_addrs().map(ToString::to_string).collect(),
        }
    }

    fn into_addr(self) -> Result<EndpointAddr> {
        let endpoint_id = self
            .endpoint_id
            .parse::<EndpointId>()
            .with_context(|| format!("parse endpoint id: {}", self.endpoint_id))?;
        let mut addr = EndpointAddr::new(endpoint_id);
        if let Some(relay_url) = self.relay_url {
            addr = addr.with_relay_url(
                relay_url
                    .parse::<RelayUrl>()
                    .with_context(|| format!("parse relay url: {relay_url}"))?,
            );
        }
        for direct_addr in self.direct_addrs {
            addr = addr.with_ip_addr(
                direct_addr
                    .parse::<SocketAddr>()
                    .with_context(|| format!("parse direct addr: {direct_addr}"))?,
            );
        }
        Ok(addr)
    }
}

pub fn save_server_addr(data_dir: impl AsRef<Path>, addr: &EndpointAddr) -> Result<()> {
    json::write_atomic_with_mode(
        &data_dir.as_ref().join(SERVER_ADDR_FILE),
        &ServerAddrFile::from_addr(addr),
        "encode JSON",
        0o660,
    )
}

pub fn load_server_addr(data_dir: impl AsRef<Path>) -> Result<EndpointAddr> {
    let path = data_dir.as_ref().join(SERVER_ADDR_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            bail!(
                "server address file {} is missing; start `drv-thru serve` first",
                path.display()
            )
        }
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let file: ServerAddrFile =
        serde_json::from_str(&text).with_context(|| format!("parse {}", path.display()))?;
    file.into_addr()
}

pub fn ticket_id(secret: &[u8; 32]) -> String {
    SecretKey::from_bytes(secret).public().to_string()
}

pub fn default_ticket_name(unix_secs: u64) -> String {
    format!("ticket-{unix_secs}")
}

fn compact_ticket_addr(addr: &EndpointAddr) -> EndpointAddr {
    let mut compact = EndpointAddr::new(addr.id);
    if let Some(relay_url) = addr.relay_urls().next().cloned() {
        return compact.with_relay_url(relay_url);
    }
    for direct_addr in addr.ip_addrs().copied() {
        compact = compact.with_ip_addr(direct_addr);
    }
    compact
}

fn now_unix_secs() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before Unix epoch")?
        .as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_round_trips() {
        let server_id = SecretKey::generate().public();
        let addr = EndpointAddr::new(server_id).with_ip_addr("127.0.0.1:1234".parse().unwrap());
        let ticket = BuildTicket {
            addr,
            secret: SecretKey::generate().to_bytes(),
        };

        let encoded = ticket.to_string();
        assert!(encoded.starts_with("drvthru"));
        let decoded: BuildTicket = encoded.parse().unwrap();

        assert_eq!(decoded.addr().id, server_id);
        assert_eq!(decoded.secret(), ticket.secret());
        assert_eq!(decoded.addr().ip_addrs().count(), 1);
    }

    #[test]
    fn ticket_prefers_relay_over_direct_addrs() {
        let addr = EndpointAddr::new(SecretKey::generate().public())
            .with_relay_url("https://use1-1.relay.n0.iroh.link./".parse().unwrap())
            .with_ip_addr("127.0.0.1:1234".parse().unwrap());
        let ticket = BuildTicket::generate(&addr);

        assert_eq!(ticket.addr().relay_urls().count(), 1);
        assert_eq!(ticket.addr().ip_addrs().count(), 0);
    }

    #[test]
    fn ticket_store_redeems_once() {
        let data_dir = temp_data_dir("redeems-once");
        let store = TicketStore::new(&data_dir);
        let addr = EndpointAddr::new(SecretKey::generate().public());
        let ticket = store
            .create(
                &addr,
                CreateTicket {
                    name: Some("test".to_string()),
                    bound_client: None,
                    expires_after: Duration::from_mins(1),
                    uses_remaining: Some(1),
                    max_build_time: "30m".to_string(),
                    max_upload_bytes: "20G".to_string(),
                },
            )
            .unwrap();
        let remote = SecretKey::generate().public();
        let stored = store.record(&ticket.id()).unwrap().unwrap();
        assert_eq!(stored.encoded_ticket, ticket.to_string());

        let record = store.redeem(&ticket.secret(), &remote).unwrap();
        assert_eq!(record.uses_remaining, Some(0));
        assert!(store.redeem(&ticket.secret(), &remote).is_err());
        assert_eq!(
            store.record(&ticket.id()).unwrap().unwrap().uses_remaining,
            Some(0)
        );

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn ticket_store_check_does_not_consume_use() {
        let data_dir = temp_data_dir("check-does-not-consume");
        let store = TicketStore::new(&data_dir);
        let addr = EndpointAddr::new(SecretKey::generate().public());
        let ticket = store
            .create(
                &addr,
                CreateTicket {
                    name: Some("test".to_string()),
                    bound_client: None,
                    expires_after: Duration::from_mins(1),
                    uses_remaining: Some(1),
                    max_build_time: "30m".to_string(),
                    max_upload_bytes: "20G".to_string(),
                },
            )
            .unwrap();
        let remote = SecretKey::generate().public();

        let checked = store.check(&ticket.secret(), &remote).unwrap();
        assert_eq!(checked.uses_remaining, Some(1));
        assert_eq!(
            store.record(&ticket.id()).unwrap().unwrap().uses_remaining,
            Some(1)
        );
        assert_eq!(
            store
                .redeem(&ticket.secret(), &remote)
                .unwrap()
                .uses_remaining,
            Some(0)
        );

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn ticket_store_revokes_ticket() {
        let data_dir = temp_data_dir("revokes-ticket");
        let store = TicketStore::new(&data_dir);
        let addr = EndpointAddr::new(SecretKey::generate().public());
        let ticket = store
            .create(
                &addr,
                CreateTicket {
                    name: Some("test".to_string()),
                    bound_client: None,
                    expires_after: Duration::from_mins(1),
                    uses_remaining: Some(1),
                    max_build_time: "30m".to_string(),
                    max_upload_bytes: "20G".to_string(),
                },
            )
            .unwrap();
        let remote = SecretKey::generate().public();

        let revoked = store.revoke(&ticket.id()).unwrap();
        assert!(revoked.revoked);
        assert!(store.check(&ticket.secret(), &remote).is_err());
        assert_eq!(store.records().unwrap().len(), 1);

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn ticket_store_enforces_bound_client() {
        let data_dir = temp_data_dir("bound-client");
        let store = TicketStore::new(&data_dir);
        let addr = EndpointAddr::new(SecretKey::generate().public());
        let bound = SecretKey::generate().public();
        let other = SecretKey::generate().public();
        let ticket = store
            .create(
                &addr,
                CreateTicket {
                    name: Some("test".to_string()),
                    bound_client: Some(bound.to_string()),
                    expires_after: Duration::from_mins(1),
                    uses_remaining: Some(1),
                    max_build_time: "30m".to_string(),
                    max_upload_bytes: "20G".to_string(),
                },
            )
            .unwrap();

        assert!(store.check(&ticket.secret(), &bound).is_ok());
        assert!(store.check(&ticket.secret(), &other).is_err());

        let _ = fs::remove_dir_all(data_dir);
    }

    #[test]
    fn ticket_store_rejects_expired() {
        let data_dir = temp_data_dir("expired");
        let store = TicketStore::new(&data_dir);
        let addr = EndpointAddr::new(SecretKey::generate().public());
        let ticket = store
            .create(
                &addr,
                CreateTicket {
                    name: None,
                    bound_client: None,
                    expires_after: Duration::from_secs(0),
                    uses_remaining: Some(1),
                    max_build_time: "30m".to_string(),
                    max_upload_bytes: "20G".to_string(),
                },
            )
            .unwrap();
        let remote = SecretKey::generate().public();

        assert!(store.redeem(&ticket.secret(), &remote).is_err());
        assert_eq!(
            store.record(&ticket.id()).unwrap().unwrap().uses_remaining,
            Some(1)
        );

        let _ = fs::remove_dir_all(data_dir);
    }

    fn temp_data_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "drv-thru-{name}-{}-{}",
            std::process::id(),
            now_unix_secs().unwrap()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
