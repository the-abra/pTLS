mod error;
mod handshake_subprotocol;

/// pTLS hash functions.
pub mod hash_functions;

use crate::io_wrapper::IoWrapper;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use error::Error;
use hash_functions::*;

/// State of the pTLS tunnel.
pub enum TunnelState {
    /// A tunnel that has not yet completed the pTLS handshake.
    Handshake,
    /// The tunnel has successfully established a secure pTLS connection.
    Application,
    /// The connection has been terminated, typically due to a fatal alert,
    /// network corruption, or a network attack.
    Terminated,
    /// Indicates that the connection was closed gracefully.
    GracefullyDisconnected,
}

/// An encrypted tunnel that implements pTLS methods and manages connection states.
#[allow(unused)]
pub struct Tunnel<R, W> {
    io_wrapper: IoWrapper<R, W>,
    local_decrypt: Arc<DecryptFunction>,
    local_signing: Arc<SigningFunction>,
    peer_encrypt: Option<EncryptFunction>,
    peer_verifying: Option<VerifyingFunction>,
    state: TunnelState,
}

impl<R, W> Tunnel<R, W>
where
    R: AsyncReadExt,
    W: AsyncWriteExt,
{
    /// Creates a new pTLS tunnel.
    pub fn new(
        (r, w): (R, W),
        local_decrypt: Arc<DecryptFunction>,
        local_signing: Arc<SigningFunction>,
    ) -> Self {
        Self {
            io_wrapper: IoWrapper::new((r, w)),
            local_decrypt,
            local_signing,
            peer_encrypt: None,
            peer_verifying: None,
            state: TunnelState::Handshake,
        }
    }
}
