use crate::{
    io_wrapper::IoWrapperError,
    sub_protocol::{handshake::HandshakeError, Alert},
};
use rsa::Error as RsaError;
use std::{error::Error as StdError, fmt::Display};

#[derive(Debug)]
pub enum Error {
    IoWrapper(IoWrapperError),
    Rsa(RsaError),
    FatalAlert(Alert),
    Terminated,
    AlreadyHandshaked,
    NoPublicKey,
    Handshake(HandshakeError),
    PaddingTooLarge,
    DecryptError,
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoWrapper(io_wrapper_error) => io_wrapper_error.fmt(f),
            Self::Rsa(rsa_error) => rsa_error.fmt(f),
            Self::FatalAlert(_) => f.write_str("got an alert"),
            Self::Terminated => f.write_str("the tunnel has been terminated"),
            Self::AlreadyHandshaked => f.write_str("a handshake is already done"),
            Self::DecryptError => f.write_str("cannot decrypt payload"),
            Self::NoPublicKey => f.write_str("handshake has not been completed yet"),
            Self::Handshake(handshake_error) => handshake_error.fmt(f),
            Self::PaddingTooLarge => f.write_str(
                "the padding size exceeds the RSA key size, making encryption impossible",
            ),
        }
    }
}

error_impl_from!(Error; IoWrapper, Rsa);
