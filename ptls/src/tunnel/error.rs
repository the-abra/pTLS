use crate::sub_protocol::handshake::HandshakeError;
use std::{error::Error as StdError, fmt::Display};

/// pTLS tunnel error types.
#[derive(Debug)]
pub enum Error {
    Handshake(HandshakeError),
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake(handshake_error) => handshake_error.fmt(f),
        }
    }
}

error_impl_from!(Error; Handshake);
