use ptls::Ptls;
use rand::thread_rng;
use rsa::{pkcs1::DecodeRsaPublicKey, RsaPrivateKey, RsaPublicKey};
use std::time::Duration;

#[tokio::main]
async fn main() {
    let server_public =
        RsaPublicKey::read_pkcs1_pem_file("./certs/public.pem").expect("Cannot read public key");
    let private_key = RsaPrivateKey::new(&mut thread_rng(), 512).unwrap();

    let mut client = tokio::net::TcpStream::connect("localhost:7811")
        .await
        .unwrap();

    // Upgrade the TCP connection to a pTLS-encrypted tunnel.
    let mut client_ptls = Ptls::new(client.split(), private_key);
    // A hard-coded certificate is required due to lack of certificate validation.
    client_ptls.set_public_key(server_public);
    client_ptls.send_public_key().await.unwrap();

    for i in 0..8 {
        client_ptls
            .send(format!("Hello from client! {i}").as_bytes())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}
