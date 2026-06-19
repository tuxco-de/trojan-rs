//! Server-side REALITY transport.
//!
//! Phase 1 scope: accept `VLESS + REALITY` over RAW TCP from Xray/sing-box
//! clients (with an empty `flow`, i.e. no XTLS Vision).  fingerprint-probe,
//! Vision, ML-DSA and a REALITY client are intentionally out of scope.
//!
//! See [`acceptor`] for the handshake/fallback design and interop caveats.

use crate::error::Error;
use std::io;

pub mod acceptor;
pub mod cert;
pub mod client_hello;
pub mod config;
pub mod crypto;

pub use acceptor::RealityAcceptor;
pub use config::RealityAcceptorConfig;

fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("reality: {}", message.to_string())).into()
}
