use std::{error::Error as StdError, fmt::Display, io::Error as IoError};

use crate::payload;

/// pTLS tunnel error types.
#[derive(Debug)]
pub enum TunnelError {
    /// An error occurred while reading from or writing to the buffer.
    Io(IoError),
    /// Provided content type is not valid, possibly due to a network failure.
    /// The connection is terminated after this error.
    UnknownContentType(u8),
    /// The message contains no payload.
    NoPayload,
    /// Provided content length invalidates reserved bytes, indicating a fatal
    /// buffer error if received from peer.
    MessageTooLong(usize),
    /// The protocol version of the message is not valid or supported.
    InappropriateVersion(u16),
}

impl StdError for TunnelError {}

impl Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(io_error) => io_error.fmt(f),
            Self::UnknownContentType(content_type) => {
                write!(f, "provided content_type {content_type} is not valid")
            }
            Self::NoPayload => {
                write!(f, "the message contains no payload")
            }
            Self::MessageTooLong(length) => {
                write!(
                    f,
                    "payload exceedes the length limit by {} bytes",
                    length - payload::MAX_PAYLOAD_LENGTH as usize
                )
            }
            Self::InappropriateVersion(version) => {
                write!(f, "the version {version} is not valid or supported",)
            }
        }
    }
}

error_impl_from!(TunnelError; Io);

#[cfg(test)]
#[test]
fn error_from() {
    let io_error = IoError::last_os_error();
    let _tunnel_erorr = TunnelError::from(io_error);
}
