use super::{Error, Tunnel};
use rsa::sha2::digest::{Digest, DynDigest};

impl<R, W, SH> Tunnel<R, W, SH> 
where
    SH: 'static + Digest + DynDigest + Send + Sync,
{
    /// Signs the payload with the tunnels's private key.
    pub fn sign<H>(&self, payload: &[u8]) -> Result<Vec<u8>, Error>
    where
        H: 'static + Digest + DynDigest + Send + Sync,
    {
        let signing_key = &self.signing_key;


        todo!();
    }

    /// Verifies the signature with the peer's private key.
    pub fn verify<H>(&self, _signature: &[u8]) -> Result<(), Error>
    where
        H: 'static + Digest + DynDigest + Send + Sync,
    {
        let _public_key = self.peer_public_key.as_ref().ok_or(Error::NoPublicKey)?;
        todo!()
    }
}

#[cfg(test)]
mod test {
    use crate::Tunnel;
    use rsa::{RsaPublicKey, sha2::Sha256};
    use std::sync::Arc;
    use tokio::io::simplex;

    macro_rules! simplex_tunnel {
        () => {{
            let private_key = random_private_key!();
            let public_key = RsaPublicKey::from(&private_key);
            let mut tunnel: Tunnel<_, _, Sha256> = Tunnel::new(
                simplex(u16::MAX as usize),
                Arc::new((private_key, public_key.clone())),
            );

            tunnel.set_peer_public_key(public_key);
            tunnel
        }};
    }

    #[test]
    fn oaep_sha256() {
        let _tunnel = simplex_tunnel!();
        todo!()
    }

    #[test]
    #[should_panic]
    fn excessive_padding() {
        todo!()
    }
}
