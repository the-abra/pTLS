use super::{Error, State, Tunnel};
use crate::sub_protocol::{handshake::HandshakeError, ContentType, Handshake};
use rsa::{
    pkcs8::DecodePublicKey,
    sha2::digest::{Digest, DynDigest},
    RsaPublicKey,
};
use tokio::io::AsyncReadExt;

impl<R, W, SH> Tunnel<R, W, SH>
where
    R: AsyncReadExt + Unpin,
    SH: 'static + Digest + DynDigest + Send + Sync,
{
    /// Starts the server handshake.
    pub async fn server_handshake<H>(&mut self) -> Result<(), Error>
    where
        H: 'static + Digest + DynDigest + Send + Sync,
    {
        match self.state {
            State::Terminated => return Err(Error::Terminated),
            State::ApplicationLayer => return Err(Error::AlreadyHandshaked),
            _ => {}
        }

        enum ClientHelloState {
            AwaitingClientHello,
            AwaitingFinished,
        }

        let mut client_hello_state = ClientHelloState::AwaitingClientHello;

        loop {
            let (content_type, payload) = self.io.receive().await?;

            match content_type {
                ContentType::ClientHello => {
                    let is_encrypted = (payload[0] & 1) == 1;

                    if is_encrypted {
                        let ech =
                            bincode::deserialize::<Handshake>(&self.decrypt::<H>(&payload[1..])?)
                                .map_err(|_| Error::DecryptError)?;
                        if let Handshake::EncryptedClientHello {
                            public_key, random, ..
                        } = ech
                        {
                            let public_key = RsaPublicKey::from_public_key_der(&public_key)
                                .map_err(|_| {
                                    Error::Handshake(HandshakeError::InappropriatePublicKey)
                                })?;
                            // TODO: Check signature
                            self.random = Some(random);
                            self.set_peer_public_key(public_key);
                            break Ok(());
                        } else {
                            return Err(Error::Handshake(HandshakeError::InappropriateMessage {
                                expected_types: vec![1],
                                got: u8::from(&ech),
                            }));
                        }
                    } else {
                        todo!()
                    }
                }
                ContentType::Handshake => {
                    todo!()
                }
                ContentType::ApplicationData => {
                    return Err(Error::Handshake(HandshakeError::InappropriateMessage {
                        expected_types: vec![
                            ContentType::ClientHello as u8,
                            ContentType::Handshake as u8,
                        ],
                        got: ContentType::ApplicationData as u8,
                    }))
                }
                ContentType::Alert => {
                    todo!()
                }
            }
        }
    }
}
