//!
//! WARNING: The [`send`] and [`receive`] objects are considered unstable.
//! Do not use those functions if you are not willing to have changes.
//!
//! [`send`]: Tunnel::send
//! [`receive`]: Tunnel::receive

mod error;
mod receive;
mod send;

use rsa::{RsaPrivateKey, RsaPublicKey};
use std::sync::Arc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

pub use error::TunnelError;

/// An encrypted tunnel implementing general pTLS methods.
pub struct Tunnel<R, W> {
    pub(crate) read: Mutex<R>,
    pub(crate) write: Mutex<W>,
    pub(crate) private_key: Arc<RsaPrivateKey>,
    pub(crate) peer_public_key: Option<RsaPublicKey>,
}

impl<R, W> Tunnel<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Creates a pTLS tunnel over provided `read` and `write` buffers.
    pub fn new((r, w): (R, W), private_key: Arc<RsaPrivateKey>) -> Self {
        Self {
            read: Mutex::new(r),
            write: Mutex::new(w),
            private_key,
            peer_public_key: None,
        }
    }

    /// Consumes `Tunnel`, returning underlying buffers.
    pub fn into_inner(self) -> (R, W) {
        (self.read.into_inner(), self.write.into_inner())
    }

    pub fn set_peer_public_key(&mut self, public_key: RsaPublicKey) {
        self.peer_public_key = Some(public_key);
    }
}

#[cfg(test)]
mod test {
    use crate::sub_protocol::ContentType;

    use super::*;
    use tokio::io::{simplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn tunnel_into_inner() {
        let tunnel = Tunnel::new(simplex(512), random_private_key!());

        let (mut r, mut w) = tunnel.into_inner();

        let data = 110;

        w.write_u8(data).await.unwrap();
        w.flush().await.unwrap();
        assert_eq!(r.read_u8().await.unwrap(), data);
    }

    #[tokio::test]
    async fn tunnel() {
        let tunnel = Tunnel::new(simplex(4096), random_private_key!());

        let payload = b"abcdefghijklmnopqrstuvwxyz1234567890";

        tunnel
            .send(ContentType::ApplicationData, payload)
            .await
            .unwrap();
        let (received_content_type, received_payload) = tunnel.receive().await.unwrap();

        assert_eq!(received_content_type, ContentType::ApplicationData);
        assert_eq!(received_payload, payload);
    }
}
