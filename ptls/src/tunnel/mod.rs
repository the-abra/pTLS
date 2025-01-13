mod error;
mod handshake_subprotocol;

/// pTLS hash functions.
pub mod hash_functions;

use crate::{
    crypto::{
        encryption::Decrypt,
        signature::Signing,
    },
    io_wrapper::IoWrapper,
};
use rsa::sha2::{
    digest::{DynDigest, FixedOutputReset},
    Digest,
};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use error::Error;

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
pub struct Tunnel<R, W, H1, H2>
where
    H1: 'static + Digest + DynDigest + Send + Sync,
    H2: Digest + FixedOutputReset,
{
    io_wrapper: IoWrapper<R, W>,
    local_decrypt: Arc<Decrypt<H1>>,
    local_signing: Arc<Signing<H2>>,
    peer_encrypt: Option<hash_functions::EncryptFunction>,
    peer_verifying: Option<hash_functions::VerifyingFunction>,
    state: TunnelState,
}

impl<R, W, H1, H2> Tunnel<R, W, H1, H2>
where
    R: AsyncReadExt,
    W: AsyncWriteExt,
    H1: 'static + Digest + DynDigest + Send + Sync,
    H2: Digest + FixedOutputReset,
{
    /// Creates a new pTLS tunnel.
    pub fn new(
        (r, w): (R, W),
        local_decrypt: Arc<Decrypt<H1>>,
        local_signing: Arc<Signing<H2>>,
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
