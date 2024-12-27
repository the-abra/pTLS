//! # pTLS - A Lightweight Custom TLS Library
//!
//! pTLS is a TLS library designed to provide a simple-to-use yet safe API.
//!
//! It implements a custom TLS protocol to achieve simplicity.
//!
//! ## Encrypted Pipes
//!
//! pTLS provides an encrypted tunnel that can be used by both servers and
//! clients.
//!
//! ```text
//!                  +------------------------+
//!                  |                        |
//!    Ptls::send    |                        |    Ptls::receive
//!        ------------------------------------------------>
//!                  |    encrypted tunnel    |
//!    Ptls::receive |                        |       Ptls::send
//!        <------------------------------------------------
//!                  |                        |
//!                  +------------------------+
//! ```
//!
//!
//! ## Examples
//!
//! You can find several client and server examles in [examples] directory.
//!
//! [examples]: https://github.com/metwse/ptls/tree/main/examples

#[macro_use]
mod macros;

mod error;

/// mTLS payload
pub mod payload;

#[cfg(test)]
mod tests;

pub use error::Error;
use payload::PtlsPayload;

use rsa::{
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    RsaPrivateKey, RsaPublicKey,
};
use std::{sync::Mutex as StdMutex, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::Mutex,
};

/// Micro TLS Tunnel is a cryptographic protocol that ensures secure
/// communication over the Internet.
#[derive(Debug)]
pub struct Ptls<R, W> {
    read: Mutex<R>,
    write: Mutex<W>,
    private_key: RsaPrivateKey,
    public_key: Option<RsaPublicKey>,
    state: StdMutex<PtlsState>,
    timeout: Option<Duration>,
}

/// pTLS state
#[derive(Debug, Clone)]
pub enum PtlsState {
    /// The client has not yet received the public key.
    AwaitingPublicKey,
    /// The pTLS tunnel is established and the certificate has been acquired.
    Authenticated,
    /// An error occurred during transmission.
    TransmitError,
}

impl<R, W> Ptls<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    /// Creates a new pTLS tunnel. The `public_key`, which should be acquired
    /// from the peer, is optional until messages are sent. It can be obtained
    /// using the `handshake` or `set_public_key` functions.
    pub fn new((read, write): (R, W), private_key: RsaPrivateKey) -> Self {
        Self {
            read: Mutex::new(read),
            write: Mutex::new(write),
            public_key: None,
            private_key,
            state: StdMutex::new(PtlsState::AwaitingPublicKey),
            timeout: None,
        }
    }

    /// Consumes the `Ptls`, returning the wrapped read and writer.
    pub fn into_inner(self) -> (R, W) {
        (self.read.into_inner(), self.write.into_inner())
    }

    /// The duration before the key exchange times out.
    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout
    }

    /// Sets the `public_key`, typically used for hard-coded keys. To ensure
    /// security, at least one of the two public keys must be hard-coded.
    pub fn set_public_key(&mut self, public_key: RsaPublicKey) {
        self.public_key = Some(public_key);
        self.set_state(PtlsState::Authenticated)
    }

    fn set_state(&self, state: PtlsState) {
        *self.state.lock().unwrap() = state
    }

    /// Returns the current state of the pTLS connection.
    pub fn get_state(&self) -> PtlsState {
        (*self.state.lock().unwrap()).clone()
    }

    /// Retrieves the `public_key` from the peer.  
    pub async fn handshake(&mut self) -> Result<(), Error> {
        match self.timeout {
            Some(duration) => {
                tokio::select! {
                    cert = self.receive() => {
                        self.handshake_inner(cert).await
                    },
                    _ = tokio::time::sleep(duration) => {
                        self.set_state(PtlsState::TransmitError);
                        Err(Error::Timeout)
                    }
                }
            }
            None => self.handshake_inner(self.receive().await).await,
        }
    }

    async fn handshake_inner(&mut self, cert: Result<Vec<u8>, Error>) -> Result<(), Error> {
        match cert {
            Ok(cert) => match RsaPublicKey::from_pkcs1_der(&cert) {
                Ok(cert) => {
                    self.set_public_key(cert);
                    Ok(())
                }
                Err(e) => {
                    self.set_state(PtlsState::TransmitError);
                    Err(Error::Pkcs1(e))
                }
            },
            Err(e) => {
                self.set_state(PtlsState::TransmitError);
                Err(e)
            }
        }
    }

    /// Sends the `public_key` to the peer for key exchange.
    pub async fn send_public_key(&mut self) -> Result<(), Error> {
        match RsaPublicKey::from(&self.private_key).to_pkcs1_der() {
            Ok(cert) => {
                let cert = cert.as_bytes();
                self.send(cert).await.unwrap();
                Ok(())
            }
            Err(e) => {
                self.set_state(PtlsState::TransmitError);
                Err(Error::Pkcs1(e))
            }
        }
    }

    /// Encrypts the data and transmits it to the peer.
    pub async fn send(&self, data: &[u8]) -> Result<(), Error> {
        match self.get_state() {
            PtlsState::Authenticated => {
                let sent: Result<(), Error> = async {
                    let stream = &mut *(self.write.lock().await);
                    PtlsPayload::new(data.to_owned())
                        .write(stream, self.public_key.as_ref().unwrap())
                        .await?;
                    Ok(())
                }
                .await;

                match sent {
                    Err(e) => {
                        self.set_state(PtlsState::TransmitError);
                        Err(e)
                    }
                    Ok(ok) => Ok(ok),
                }
            }
            PtlsState::AwaitingPublicKey => Err(Error::NotReady),
            PtlsState::TransmitError => Err(Error::SocketDied),
        }
    }

    /// Receives and decrypts data from the peer.
    pub async fn receive(&self) -> Result<Vec<u8>, Error> {
        match self.get_state() {
            PtlsState::TransmitError => Err(Error::SocketDied),
            _ => {
                let received = async {
                    let stream = &mut *(self.read.lock().await);
                    let payload = PtlsPayload::collect_once(stream, &self.private_key).await?;
                    Ok(payload.payload)
                }
                .await;

                match received {
                    Err(e) => {
                        self.set_state(PtlsState::TransmitError);
                        Err(e)
                    }
                    Ok(ok) => Ok(ok),
                }
            }
        }
    }
}
