use rsa::{signature::Error as SignatureError, Error as RsaError};
use std::{error::Error as StdError, fmt::Display};

/// Crypto error types.
#[derive(Debug)]
pub enum Error {
    HashFunctionOutputTooLarge,
    Rsa(RsaError),
    Signature(SignatureError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HashFunctionOutputTooLarge => f.write_str(
                "output of the hash function is too large to encrypt with the provided public key",
            ),
            Self::Rsa(rsa_error) => rsa_error.fmt(f),
            Self::Signature(signature_error) => signature_error.fmt(f),
        }
    }
}

impl StdError for Error {}

error_impl_from!(Error; Rsa, Signature);
