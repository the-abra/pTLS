//!
//! pTLS provides three sub-protocols for categorizing and handling messages.
//!
//! Typically, during a pTLS connection, [`ApplicationData`] protocols follow
//! the [`Handshake`] phase. [`Alert`] messages are sent if an error occurs,
//! though this should not happen with properly implemented pTLS in stable
//! networks.
//!
//! [`Handshake`]: sub_protocol::Handshake
//! [`ApplicationData`]: sub_protocol::ApplicationData
//! [`Alert`]: sub_protocol::Alert

/// The alerting sub-protocol notifies the client of errors.
pub mod alert;
/// The application layer of pTLS.
pub mod application_data;
/// A sub-protocol for key exchange.
pub mod handshake;

pub use alert::Alert;
pub use application_data::ApplicationData;
pub use handshake::Handshake;

#[derive(Debug, PartialEq, Eq)]
pub enum ContentType {
    Handshake = 0,
    ApplicationData = 1,
    Alert = 2,
}

impl TryFrom<u8> for ContentType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Handshake),
            1 => Ok(Self::ApplicationData),
            2 => Ok(Self::Alert),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn alert_equality() {
        use super::{alert::HandshakeError, Alert::*, *};

        assert_eq!(InvalidRandom, InvalidRandom);
        assert_eq!(
            InappropriateMessage {
                expected_types: vec![ContentType::Handshake],
                got: ContentType::ApplicationData
            },
            InappropriateMessage {
                expected_types: vec![ContentType::Handshake],
                got: ContentType::ApplicationData
            },
        );
        assert_eq!(
            HandshakeError(HandshakeError::InvalidRandom),
            HandshakeError(HandshakeError::InvalidRandom)
        );
        assert_eq!(
            HandshakeError(HandshakeError::InappropriateMessage {
                expected_types: vec![3],
                got: 0
            }),
            HandshakeError(HandshakeError::InappropriateMessage {
                expected_types: vec![u8::from(&Handshake::Finished {
                    random: 0,
                    random_signature: vec![]
                })],
                got: u8::from(&Handshake::ClientHello { public_key: vec![] })
            }),
        );
    }
}
