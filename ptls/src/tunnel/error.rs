use crate::{
    crypto::CryptoError, io_wrapper::IoWrapperError, sub_protocol::handshake::HandshakeError,
};
use std::{error::Error as StdError, fmt::Display};

/// pTLS tunnel error types.
#[derive(Debug)]
pub enum Error {
    Handshake(HandshakeError),
    Crypto(CryptoError),
    IoWrapper(IoWrapperError),
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handshake(handshake_error) => handshake_error.fmt(f),
            Self::Crypto(crypto_error) => crypto_error.fmt(f),
            Self::IoWrapper(io_wrapper_error) => io_wrapper_error.fmt(f),
        }
    }
}

error_impl_from!(Error; Handshake, Crypto, IoWrapper);
