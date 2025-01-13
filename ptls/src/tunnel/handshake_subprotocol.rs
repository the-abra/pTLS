use super::{EncryptFunction, Error, HashFunction, Tunnel, VerifyingFunction};
use crate::{
    io_wrapper::IoWrapperError,
    sub_protocol::{
        handshake::{self, HandshakeContentType, HandshakeError, ServerHello},
        ContentType,
    },
};
use rsa::{pkcs1::EncodeRsaPublicKey, pkcs8::DecodePublicKey, RsaPublicKey};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl<R, W> Tunnel<R, W>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    /// Starts the server handshake.
    pub async fn server_handshake(&mut self) -> Result<(), Error> {
        let mut client_hello = false;
        loop {
            let (content_type, mut payload) = self.io_wrapper.receive().await?;
            if payload.len() <= 2 {
                return Err(Error::IoWrapper(IoWrapperError::NoPayload));
            }

            let handshake_content_type = HandshakeContentType::try_from(payload[0])?;

            if !matches!(content_type, ContentType::Handshake) {
                return Err(Error::Handshake(HandshakeError::InvalidContentType));
            }
            if !matches!(handshake_content_type, HandshakeContentType::ClientHello) {
                self.local_decrypt.decrypt_owned(&mut payload)?;
            }

            let mut credentials = None;
            let mut random = None;

            match handshake_content_type {
                HandshakeContentType::EncryptedClientHello if !client_hello => {
                    let ech: handshake::EncryptedClientHello =
                        bincode::deserialize(&payload).map_err(|_| Error::InvalidPayload)?;

                    credentials = Some((ech.public_key, ech.signature_hf, ech.padding_hf));
                    random = Some((ech.random, ech.random_signature));
                }
                HandshakeContentType::ClientHello if !client_hello => {
                    let ch: handshake::ClientHello =
                        bincode::deserialize(&payload).map_err(|_| Error::InvalidPayload)?;

                    credentials = Some((ch.public_key, ch.signature_hf, ch.padding_hf));
                }
                HandshakeContentType::Finished if client_hello => {
                    let finished: handshake::Finished =
                        bincode::deserialize(&payload).map_err(|_| Error::InvalidPayload)?;

                    random = Some((finished.random, finished.random_signature));
                }
                _ => return Err(Error::Handshake(HandshakeError::InvalidContentType)),
            }

            if let Some((public_key, signature_hf, padding_hf)) = credentials {
                let public_key = RsaPublicKey::from_public_key_der(&public_key)
                    .map_err(|_| Error::InvalidPublicKey)?;
                let signature_hf = HashFunction::try_from(signature_hf)?;
                let padding_hf = HashFunction::try_from(padding_hf)?;
                let signed_public = self.signed_public.as_ref().ok_or(Error::InvalidPayload)?;
                self.peer_encrypt =
                    Some(EncryptFunction::try_new(&padding_hf, public_key.clone())?);
                self.peer_verifying = Some(VerifyingFunction::try_new(&signature_hf, public_key)?);

                if handshake_content_type == HandshakeContentType::ClientHello {
                    let server_hello = ServerHello {
                        public_key: signed_public
                            .public_key
                            .to_pkcs1_der()
                            .map_err(|_| Error::UnexceptedError)?
                            .to_vec(),
                        expries_at: signed_public.expries_at,
                        padding_hf: self.local_decrypt.hash_type() as u8,
                        signature_hf: self.local_signing.hash_type() as u8,
                        trusted_authority_id: signed_public.trusted_authority_id,
                        signature: signed_public.signature.clone(),
                    };

                    let mut payload = vec![HandshakeContentType::ServerHello as u8];
                    payload.append(
                        &mut self
                            .peer_encrypt
                            .as_ref()
                            .ok_or(Error::Handshake(HandshakeError::InvalidContentType))?
                            .encrypt(
                                &bincode::serialize(&server_hello)
                                    .map_err(|_| Error::UnexceptedError)?,
                            )?,
                    );

                    self.send(ContentType::Handshake, &payload).await?;
                }

                client_hello = true;
            }

            if let Some((random, random_signature)) = random {
                self.peer_verifying
                    .as_ref()
                    .ok_or(Error::Handshake(HandshakeError::InvalidContentType))?
                    .verify(&random, &random_signature)?;
                break;
            }
        }
        Ok(())
    }

    /// Starts a full handshake.
    pub async fn full_handshake(&mut self) {
        todo!()
    }
}
