#[tokio::test]
async fn full_handshake() {
    use super::*;

    let (mut server, mut peer) = tunnel_pair!();

    server.set_signed_public_key(Arc::new(SignedPublicKey {
        public_key: RsaPublicKey::from((*server.local_decrypt).as_ref()),
        expries_at: 0,
        trusted_authority_id: 0,
        signature: vec![],
    }));

    tokio::select! {
        result = peer.full_handshake() => result.unwrap(),
        result = server.server_handshake() => result.unwrap()
    };
}
