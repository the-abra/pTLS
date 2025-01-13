//  use super::Tunnel;
//  use rsa::sha2::digest::{Digest, DynDigest, FixedOutputReset};
//  use tokio::io::{AsyncReadExt, AsyncWriteExt};

//  impl<R, W, H1, H2> Tunnel<R, W, H1, H2>
//  where
//      R: AsyncReadExt,
//      W: AsyncWriteExt,
//      H1: 'static + Digest + DynDigest + Send + Sync,
//      H2: Digest + FixedOutputReset,
//  {
//      pub async fn server_handshake(&mut self) {
//          todo!()
//      }
//  }
