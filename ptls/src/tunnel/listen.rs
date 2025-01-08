use super::{Error, Tunnel};
use crate::sub_protocol::ContentType;
use serde::de::DeserializeOwned;
use tokio::{io::AsyncReadExt, sync::mpsc::Sender};

impl<R, W> Tunnel<R, W>
where
    R: AsyncReadExt + Unpin,
{
    pub async fn listen<T: DeserializeOwned>(
        &self,
        application_handler: Sender<T>,
    ) -> Result<(), Error> {
        loop {
            let (content_type, payload) = self.io.receive().await?;

            match content_type {
                ContentType::ClientHello => {
                    todo!()
                }
                ContentType::Handshake => {
                    todo!()
                }
                ContentType::ApplicationData => {
                    // TODO: decrypt
                    // TODO: error handling
                    let data = bincode::deserialize(&payload).unwrap();
                    application_handler.send(data).await.unwrap();
                }
                ContentType::Alert => {
                    todo!()
                }
            }
        }
    }
}
