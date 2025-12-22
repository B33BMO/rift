use thiserror::Error;

#[derive(Error, Debug)]
pub enum RiftError {
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Connection failed: {0}")]
    Connection(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Hole punch failed after {attempts} attempts")]
    HolePunchFailed { attempts: u32 },

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Beacon unreachable: {0}")]
    BeaconUnreachable(String),

    #[error("Relay required but unavailable")]
    RelayUnavailable,

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}

pub type Result<T> = std::result::Result<T, RiftError>;
