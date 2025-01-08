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

/// All content types except for `ClientHello` is encrypted.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum ContentType {
    ClientHello = 0,
    Handshake = 1,
    ApplicationData = 2,
    Alert = 3,
}

impl TryFrom<u8> for ContentType {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::ClientHello),
            1 => Ok(Self::Handshake),
            2 => Ok(Self::ApplicationData),
            3 => Ok(Self::Alert),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
#[test]
fn alert_equality() {
    use alert::HandshakeError;
    use Alert::*;

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
