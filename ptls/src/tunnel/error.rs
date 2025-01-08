use crate::{io_wrapper::IoWrapperError, sub_protocol::Alert};
use std::{error::Error as StdError, fmt::Display};

#[derive(Debug)]
pub enum Error {
    IoWrapper(IoWrapperError),
    FatalAlert(Alert),
}

impl StdError for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FatalAlert(_) => f.write_str("got an alert"),
            Self::IoWrapper(io_wrapper_error) => io_wrapper_error.fmt(f),
        }
    }
}

error_impl_from!(Error; IoWrapper);
