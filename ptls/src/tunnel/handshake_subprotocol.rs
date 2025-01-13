use super::{Error, Tunnel};
use crate::{
    io_wrapper::IoWrapperError,
    sub_protocol::{
        handshake::{HandshakeContentType, HandshakeError},
        ContentType,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

impl<R, W> Tunnel<R, W>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    /// Starts the server handshake.
    pub async fn server_handshake(&mut self) -> Result<(), Error> {
        loop {
            let (content_type, mut payload) = self.io_wrapper.receive().await?;
            if payload.len() <= 1 {
                return Err(Error::IoWrapper(IoWrapperError::NoPayload));
            }

            match content_type {
                ContentType::Handshake => {
                    let handshake_content_type = HandshakeContentType::try_from(payload[0])?;

                    if matches!(handshake_content_type, HandshakeContentType::EncryptedClientHello) {
                        self.local_decrypt.decrypt_owned(&mut payload)?;
                    }
                }
                ContentType::Alert => break,
                _ => return Err(Error::Handshake(HandshakeError::InvalidContentType)),
            }
        }
        Ok(())
    }

    /// Starts a full handshake.
    pub async fn full_handshake(&mut self) {
        todo!()
    }
}
