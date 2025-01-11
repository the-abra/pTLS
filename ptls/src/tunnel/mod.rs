mod encryption;
mod error;
mod handshake;
mod signature;

use crate::io_wrapper::IoWrapper;
use rsa::{
    pss::{BlindedSigningKey, VerifyingKey},
    sha2::digest::{Digest, DynDigest},
    RsaPrivateKey, RsaPublicKey,
};
use std::sync::Arc;

pub use error::Error;

/// An encrypted tunnel that implements pTLS methods and manages connection states.
pub struct Tunnel<R, W, SH>
where
    SH: 'static + Digest + DynDigest + Send + Sync,
{
    pub(super) io: IoWrapper<R, W>,
    pub(super) signing_key: BlindedSigningKey<SH>,
    pub(super) key_pair: Arc<(RsaPrivateKey, RsaPublicKey)>,
    pub(super) peer_public_key: Option<RsaPublicKey>,
    pub(super) peer_verifying_key: Option<VerifyingKey<SH>>,
    pub(super) state: State,
    pub(super) random: Option<u64>,
}

impl<R, W, SH> Tunnel<R, W, SH>
where
    SH: 'static + Digest + DynDigest + Send + Sync,
{
    /// Creates a new pTLS tunnel.
    pub fn new((r, w): (R, W), key_pair: Arc<(RsaPrivateKey, RsaPublicKey)>) -> Self {
        Self {
            io: IoWrapper::new((r, w)),
            signing_key: BlindedSigningKey::<SH>::new(key_pair.0.clone()),
            key_pair,
            peer_public_key: None,
            peer_verifying_key: None,
            state: State::Handshake,
            random: None,
        }
    }

    /// Downgrades the connection to an unencrypted state. Consumes `Tunnel`,
    /// returning underlying `read` and `write`.
    pub fn downgrade(self) -> (R, W) {
        self.io.into_inner()
    }

    pub fn set_peer_public_key(&mut self, peer_public_key: RsaPublicKey) {
        self.peer_verifying_key = Some(VerifyingKey::<SH>::new(peer_public_key.clone()));
        self.peer_public_key = Some(peer_public_key);
    }
}

/// State of the pTLS tunnel.
pub enum State {
    Handshake,
    ApplicationLayer,
    Terminated,
}

#[cfg(test)]
#[tokio::test]
async fn tunnel_downgrade() {
    use rsa::sha2::Sha512;
    use tokio::io::{simplex, AsyncReadExt, AsyncWriteExt};

    let private_key = random_private_key!();
    let public_key = RsaPublicKey::from(&private_key);

    let tunnel: Tunnel<_, _, Sha512> = Tunnel::new(simplex(4096), Arc::new((private_key, public_key)));

    let (mut r, mut w) = tunnel.downgrade();

    w.write_u8(123).await.unwrap();
    w.flush().await.unwrap();

    assert_eq!(r.read_u8().await.unwrap(), 123);
}
