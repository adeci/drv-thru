use serde::{Deserialize, Serialize};

pub const ALPN: &[u8] = b"drv-thru/0";
pub const VERSION: u32 = 0;

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Message {
    Hello(Hello),
    AuthTrustedClient,
    AuthTicket(AuthTicket),
    AuthOk(AuthOk),
    BuildRequest(BuildRequest),
    BuildPaths(PathListChunk),
    BuildQueued,
    MissingPaths(PathListChunk),
    InputUploadReady,
    BuildStarted,
    NixLog(NixLog),
    BuildFinished(BuildFinished),
    OutputClosure(PathListChunk),
    OutputRequest(PathListChunk),
    OutputDownloadReady(OutputDownloadReady),
    Done,
    Error(ErrorMessage),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Hello {
    pub version: u32,
    pub node_id: String,
}

#[derive(Serialize, Deserialize)]
pub struct AuthTicket {
    pub secret: [u8; 32],
}

impl std::fmt::Debug for AuthTicket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthTicket")
            .field("secret", &"<redacted>")
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthOk {
    pub client_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildRequest {
    pub installable: String,
    pub drv_path: String,
    pub output_paths: Vec<String>,
    pub output_mode: OutputMode,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PathListChunk {
    pub paths: Vec<String>,
    pub done: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NixLog {
    pub line: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BuildFinished {
    pub success: bool,
    pub output_paths: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OutputDownloadReady {
    pub path_count: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputMode {
    Nom,
    Plain,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorMessage {
    pub message: String,
}
