#[cfg(test)]
macro_rules! tunnel_pair {
    () => {{
        use crate::tunnel::*;
        use tokio::io::simplex;

        let (peer_r, w) = simplex(u16::MAX as usize);
        let (r, peer_w) = simplex(u16::MAX as usize);
        let server_private = random_private_key!(512);
        let server_decrypt =
            DecryptFunction::try_new(&HashFunction::Sha224, server_private.clone()).unwrap();
        let server_signing =
            SigningFunction::try_new(&HashFunction::Sha224, server_private).unwrap();

        let peer_private = random_private_key!(512);
        let peer_decrypt =
            DecryptFunction::try_new(&HashFunction::Sha224, peer_private.clone()).unwrap();
        let peer_signing = SigningFunction::try_new(&HashFunction::Sha224, peer_private).unwrap();

        let server = Tunnel::new((r, w), Arc::new(server_decrypt), Arc::new(server_signing));
        let peer = Tunnel::new(
            (peer_r, peer_w),
            Arc::new(peer_decrypt),
            Arc::new(peer_signing),
        );

        (server, peer)
    }};
    (auth) => {{
        use crate::tunnel::*;

        let (mut server, mut peer) = tunnel_pair!();

        let peer_public = RsaPublicKey::from((*peer.local_decrypt).as_ref());
        let server_public = RsaPublicKey::from((*server.local_decrypt).as_ref());

        server
            .set_peer_public_key(peer_public, &HashFunction::Sha224, &HashFunction::Sha224)
            .unwrap();
        peer.set_peer_public_key(server_public, &HashFunction::Sha224, &HashFunction::Sha224)
            .unwrap();

        (server, peer)
    }};
}

#[cfg(test)]
macro_rules! recursive_tunnel {
    () => {{
        use crate::tunnel::*;
        use tokio::io::simplex;

        let (r, w) = simplex(u16::MAX as usize);
        let private_key = random_private_key!(512);

        let decrypt = DecryptFunction::try_new(&HashFunction::Sha224, private_key.clone()).unwrap();
        let signing = SigningFunction::try_new(&HashFunction::Sha224, private_key).unwrap();

        let tunnel = Tunnel::new((r, w), Arc::new(decrypt), Arc::new(signing));

        tunnel
    }};
    (auth) => {{
        use crate::tunnel::*;

        let mut tunnel = recursive_tunnel!();

        let public_key = RsaPublicKey::from((*tunnel.local_decrypt).as_ref());

        tunnel
            .set_peer_public_key(public_key, &HashFunction::Sha224, &HashFunction::Sha224)
            .unwrap();

        tunnel
    }};
}
