#[macro_use]
mod macros;

/// pTLS protocol version
pub const PTLS_VERSION: u16 = 0;

/// pTLS tunnel that wraps a connection.
pub mod tunnel;

/// Sub-protocol messages and error types.
pub mod sub_protocol;

/// Items used for payload sending or receiving.
pub mod payload;

#[doc(inline)]
pub use payload::MAX_PAYLOAD_LENGTH;
pub use tunnel::Tunnel;
