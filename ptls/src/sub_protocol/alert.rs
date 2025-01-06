//!
//! pTLS provided an [`Alert`] protocol to indicate key update, closure
//! information and errors. Unlike [`ApplicationData`], alert messages may not
//! encrypted.
//!
//! Alert messages describe the alert and include an 8-bit integer indicating
//! whether the error is fatal and if the message is encrypted.
//!
//! Alerts sent before the `handshake` phase are unencrypted, while errors
//! after the `handshake` phase must be sent encrypted. All unencrypted alerts
//! are ignored after a successful [`Finished`] or [`EncryptedClientHello`]
//! phase in the `handshake`.
//!
//! [`Finished`]: Handshake::Finished
//! [`EncryptedClientHello`]: Handshake::EncryptedClientHello

use super::ContentType;

/// Message types are sent in the `alert` sub-protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum Alert {
    /// Error occuring during the `handshake` phase, are always fatal.
    HandshakeError(HandshakeError),

    /// The random sent in [`ApplicationData`] or [`Alert`] itself is not
    /// valid.
    ///
    /// [`ApplicationData`]: super::ApplicationData
    InvalidRandom,

    /// An invalid message was received. This should not occur in properly
    /// implemented pTLS systems.
    DecryptError,

    /// Received a pTLS message that is not valid right now.
    InappropriateMessage {
        expected_types: Vec<ContentType>,
        got: ContentType,
    },

    /// Updates the public key of the peer.
    KeyUpdate { public_key: Vec<u8> },
}

/// Errors may occur during the `handshake` sub-protocol.
#[derive(Debug, PartialEq, Eq)]
pub enum HandshakeError {
    /// The public key provided by peer is not a valid PKCS8 key in DER
    /// format.
    InappropriatePublicKey,

    /// The certificate authority is not a known certificate issuer.
    UnknownCa,

    /// The signature provided by peer is not valid.
    InvalidSignature,

    /// The random sent by peer is not valid.
    InvalidRandom,

    /// Received a `handshake`message that is not valid right now.
    InappropriateMessage { expected_types: Vec<u8>, got: u8 },
}
