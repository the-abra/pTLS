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
use payload::{PtlsPayload, PtlsPayloadType};

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
        let payload;

        match self.timeout {
            Some(duration) => {
                tokio::select! {
                    received_cert = self.receive_inner() => {
                        payload = received_cert;
                    },
                    _ = tokio::time::sleep(duration) => {
                        self.set_state(PtlsState::TransmitError);
                        return Err(Error::Timeout);
                    }
                }
            }
            None => {
                payload = self.receive_inner().await;
            },
        };

        match payload {
            Ok(payload) => {
                match payload.content_type {
                    PtlsPayloadType::PublicKey => {
                        match RsaPublicKey::from_pkcs1_der(&payload.payload) {
                            Ok(cert) => {
                                self.set_public_key(cert);
                                Ok(())
                            }
                            Err(e) => {
                                self.set_state(PtlsState::TransmitError);
                                Err(Error::Pkcs1(e))
                            }
                        }
                    }
                    _ => {
                        self.set_state(PtlsState::TransmitError);
                        Err(Error::Payload(payload::Error::InvalidContentType))
                    }
                }
            }
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
                self.send_inner(cert, PtlsPayloadType::PublicKey).await.unwrap();
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
        self.send_inner(data, PtlsPayloadType::EncryptedTraffic).await
    }

    async fn send_inner(&self, data: &[u8], content_type: PtlsPayloadType) -> Result<(), Error> {
        match self.get_state() {
            PtlsState::Authenticated => {
                let sent: Result<(), Error> = async {
                    let stream = &mut *(self.write.lock().await);
                    PtlsPayload::new(data.to_owned(), content_type)
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
        let received = self.receive_inner().await?;
        match received.content_type {
            PtlsPayloadType::EncryptedTraffic => Ok(received.payload),
            _ => {
                self.set_state(PtlsState::TransmitError);
                Err(Error::Payload(payload::Error::InvalidContentType))
            }
        }
    }

    async fn receive_inner(&self) -> Result<PtlsPayload, Error> {
        match self.get_state() {
            PtlsState::TransmitError => Err(Error::SocketDied),
            _ => {
                let received = async {
                    let stream = &mut *(self.read.lock().await);
                    let payload = PtlsPayload::collect_once(stream, &self.private_key).await?;
                    Ok(payload)
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
