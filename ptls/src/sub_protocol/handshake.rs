//!
//! Figure below shows the full pTLS handshake:
//! ```text
//!        Client                                           Server
//!
//! Key  ^ ClientHello
//! Exch v    public_key           ------->
//!
//!                                                 [ServerHello]  ^ Key
//!                                                  public_key    | Exch
//!                                       thrusted_authority_id    |
//!                                <-------           signature    v
//!
//! Auth ^ {Finished}
//!      |   random
//!      v   random_signature      ------->
//!
//!        {ApplicationData}       <------>       [ApplicationData]
//!
//!
//!     [] Indicates messages protected using client's public key.
//!     {} Indicates messages protected using server's public key.
//! ```
//!
//! The full handshake can be thought of as having two phases (indicated in
//! diagram above):
//!
//! - `Key Exchange`: Establish shared keying material. Everything after this
//!   phase is encrypted.
//!
//! - `Authentication`: Authenticate the server and provide message confirmation
//!   random.
//!
//! In the `Key Exchange` phase, the client sends a [`ClientHello`] message,
//! which includes its public key. The server processes the [`ClientHello`] and
//! responds with a [`ServerHello`] containing its public key. Finally, the
//! client and server exchange a [`Finished`] message during the
//! `Authentication` phase. This [`Finished`] message includes a random used to
//! prevent message forgery.
//!
//!
//! Figure below shows the basic pTLS handshake:
//! ```text
//!        Client                                           Server
//!
//! Key  ^ {EncryptedClientHello}
//! Exch v    public_key
//! Auth ^    random
//! exch v    random_signature     ------->
//!
//!        {ApplicationData}       <------>       [ApplicationData]
//! ```
//!
//! The basic handshake is a streamlined version of the full handshake,
//! recommended when the server's public key is already known. It establishes
//! a connection with a single [`EncryptedClientHello`] message, expediting
//! both the `Key Exchange` and `Authentication` phases.
//! [`EncryptedClientHello`] combines the [`ClientHello`] and [`Finished`]
//! messages into a single package.
//!
//! Typically, the basic handshake is used for reconnecting.
//!
//! [`ClientHello`]: Handshake::ClientHello
//! [`ServerHello`]: Handshake::ServerHello
//! [`Finished`]: Handshake::Finished
//! [`EncryptedClientHello`]: Handshake::EncryptedClientHello

/// Messages sent during the `handshake` sub-protocol.
pub enum Handshake {
    /// When a client first connects to a server, it is required to send the
    /// `ClientHello` or `EncryptedClientHello` as its first pTLS message.
    ClientHello { public_key: Vec<u8> },

    /// This is an encrypted version of the `ClientHello`. Combines the
    /// properties of `Finished` and `ClientHello`.
    EncryptedClientHello {
        public_key: Vec<u8>,
        random: u64,
        random_signature: Vec<u8>,
    },

    /// The server will send this message in response to a ClientHello message
    /// to proceed with the handshake.
    ServerHello {
        public_key: Vec<u8>,
        trusted_authority_id: u64,
        signature: Vec<u8>,
    },

    /// The `Finished` message concludes the `Handshake` phase. After sending a
    /// `Finished` message, the peer or the server can start sending
    /// `ApplicationData`.
    Finished {
        /// A random 64-bit integer used to prevent message forgery. The client
        /// must include this value with `ApplicationData`.
        random: u64,
        random_signature: Vec<u8>,
    },
}

impl<'a> From<&'a Handshake> for u8 {
    fn from(handshake: &'a Handshake) -> Self {
        match handshake {
            Handshake::ClientHello { .. } => 0,
            Handshake::EncryptedClientHello { .. } => 1,
            Handshake::ServerHello { .. } => 2,
            Handshake::Finished { .. } => 3,
        }
    }
}
