use rsa::sha2::{
    digest::{DynDigest, FixedOutputReset},
    Digest,
};
use std::sync::Arc;

use crate::{
    crypto::{
        encryption::{Decrypt, Encrypt},
        signature::{Signing, Verifying},
    },
    io_wrapper::IoWrapper,
};

pub struct Tunnel<R, W, H1, H2, H3, H4>
where
    H1: 'static + Digest + DynDigest + Send + Sync,
    H2: Digest + FixedOutputReset,
    H3: 'static + Digest + DynDigest + Send + Sync,
    H4: Digest + FixedOutputReset,
{
    io_wrapper: IoWrapper<R, W>,
    local_decrypt: Arc<Decrypt<H1>>,
    local_signing: Arc<Signing<H2>>,
    peer_encrypt: Arc<Encrypt<H3>>,
    peer_verifying: Arc<Verifying<H4>>,
}
