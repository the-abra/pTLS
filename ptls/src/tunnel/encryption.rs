use super::{Error, Tunnel};
use rand::rngs::OsRng;
use rsa::{
    sha2::digest::{Digest, DynDigest},
    traits::PublicKeyParts,
    Oaep,
};

impl<R, W, SH> Tunnel<R, W, SH> 
where
    SH: 'static + Digest + DynDigest + Send + Sync,
{
    /// Encrypts the payload with the peer's public key.
    pub fn encrypt<H>(&self, payload: &[u8]) -> Result<Vec<u8>, Error>
    where
        H: 'static + Digest + DynDigest + Send + Sync,
    {
        let public_key = self.peer_public_key.as_ref().ok_or(Error::NoPublicKey)?;
        let mut padding = Oaep::new::<H>();

        // OAEP padding adds an overhead of 2 * hash_output_size + 2 bytes.
        let overhead = padding.digest.output_size() * 2 + 2;
        // RSA encryption is limited to the key size in bytes.
        let block_size = public_key.n().bits() / 8;
        // It is impossible to encrypt when OAEP overhead exceeds RSA size.
        if overhead >= block_size {
            return Err(Error::PaddingTooLarge);
        }

        let encrypted_block_size = block_size - overhead;

        let block_count = payload.len().div_ceil(encrypted_block_size);
        let mut encrypted = Vec::with_capacity(block_size * block_count);

        for i in 0..block_count {
            encrypted.append(&mut public_key.encrypt(
                &mut OsRng,
                padding,
                &payload
                    [i * encrypted_block_size..((i + 1) * encrypted_block_size).min(payload.len())],
            )?);

            if i == block_count - 1 {
                break;
            }
            padding = Oaep::new::<H>();
        }

        Ok(encrypted)
    }

    /// Decrypts the payload with the tunnel's private key.
    pub fn decrypt<H>(&self, payload: &[u8]) -> Result<Vec<u8>, Error>
    where
        H: 'static + Digest + DynDigest + Send + Sync,
    {
        let private_key = &self.key_pair.0;
        let mut padding = Oaep::new::<H>();

        let overhead = padding.digest.output_size() * 2 + 2;
        let block_size = private_key.n().bits() / 8;
        if overhead >= block_size {
            return Err(Error::PaddingTooLarge);
        }

        let block_count = payload.len() / block_size;
        let mut decrypted: Vec<u8> = Vec::with_capacity((block_size - overhead) * block_count);

        for i in 0..block_count {
            decrypted.append(&mut private_key.decrypt(
                padding,
                &payload[i * block_size..((i + 1) * block_size).min(payload.len())],
            )?);

            if i == block_count - 1 {
                break;
            }
            padding = Oaep::new::<H>();
        }

        Ok(decrypted)
    }
}

#[cfg(test)]
mod test {
    use crate::Tunnel;
    use rsa::{
        sha2::{Sha256, Sha512},
        RsaPublicKey,
    };
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
        let tunnel = simplex_tunnel!();

        let test_payload = &[0, 1, 2, 3, 4, 5, 6, 7].repeat(32);
        let encrypted = tunnel.encrypt::<Sha256>(test_payload).unwrap();
        assert_eq!(*test_payload, tunnel.decrypt::<Sha256>(&encrypted).unwrap());
    }

    #[test]
    #[should_panic]
    fn excessive_padding() {
        let tunnel = simplex_tunnel!();

        tunnel.encrypt::<Sha512>(&[1]).unwrap();
    }
}
