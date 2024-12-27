use ptls::Ptls;
use rsa::{pkcs1::DecodeRsaPrivateKey, RsaPrivateKey};

#[tokio::main]
async fn main() {
    let server_private =
        RsaPrivateKey::read_pkcs1_pem_file("./certs/private.pem").expect("Cannot read private key");

    let server = tokio::net::TcpListener::bind("localhost:7811")
        .await
        .unwrap();

    loop {
        let mut peer = if let Ok((peer, _)) = server.accept().await {
            peer
        } else {
            continue;
        };

        // Handle the connection.
        tokio::spawn({
            let server_private = server_private.clone();
            async move {
                let mut server_ptls = Ptls::new(peer.split(), server_private);
                // Upgrade the TCP connection to a pTLS-encrypted tunnel.
                if server_ptls.handshake().await.is_err() {
                    return;
                }

                while let Ok(data) = server_ptls.receive().await {
                    match std::str::from_utf8(&data) {
                        Ok(str) => println!("Received {str:?}"),
                        Err(_) => println!("Received bytes {data:?}"),
                    }
                }
            }
        });
    }
}
