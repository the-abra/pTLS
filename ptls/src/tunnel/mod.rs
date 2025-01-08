mod error;
mod listen;

use crate::io_wrapper::IoWrapper;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;

pub use error::Error;

/// An encrypted tunnel that implements pTLS methods and manages connection states.
pub struct Tunnel<R, W> {
    io: IoWrapper<R, W>,
    key_pair: Arc<(RsaPrivateKey, RsaPublicKey)>,
    peer_public_key: Option<RsaPublicKey>,
}

impl<R, W> Tunnel<R, W> {
    /// Creates a new pTLS tunnel.
    pub fn new((r, w): (R, W), key_pair: Arc<(RsaPrivateKey, RsaPublicKey)>) -> Self {
        Self {
            io: IoWrapper::new((r, w)),
            key_pair,
            peer_public_key: None,
        }
    }

    /// Downgrades the connection to an unencrypted state. Consumes `Tunnel`,
    /// returning underlying `read` and `write`.
    pub fn downgrade(self) -> (R, W) {
        self.io.into_inner()
    }
}
