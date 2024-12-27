use super::*;
use payload::max_payload_size;
use tokio::io::simplex;

#[tokio::test]
async fn mtls_max_buffer() {
    use rand::thread_rng;

    let mut rng = thread_rng();

    let server_private = RsaPrivateKey::new(&mut rng, 512).unwrap();
    let server_public = RsaPublicKey::from(&server_private);
    let client_private = RsaPrivateKey::new(&mut rng, 512).unwrap();

    let (mock_server_read, mock_client_write) = simplex(u16::MAX as usize);
    let (mock_client_read, mock_server_write) = simplex(u16::MAX as usize);

    let mut mock_server_ptls = Ptls::new((mock_server_read, mock_server_write), server_private);
    let mut mock_client_ptls = Ptls::new((mock_client_read, mock_client_write), client_private);

    mock_client_ptls.set_public_key(server_public);
    let (client_send, server_handshake) = tokio::join! {
        mock_client_ptls.send_public_key(),
        mock_server_ptls.handshake(),
    };
    client_send.unwrap();
    server_handshake.unwrap();

    let data = vec![1; max_payload_size(64) as usize];

    mock_client_ptls.send(&data).await.unwrap();
    assert_eq!(data, mock_server_ptls.receive().await.unwrap());
}
