use crate::error::Error;
use std::{io, net::IpAddr};

pub mod acceptor;

const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

pub(super) fn default_handshake_timeout_secs() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_SECS
}

fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("tls: {}", message.to_string())).into()
}

pub(super) fn validate_sni(sni: &str) -> io::Result<()> {
    if sni.is_empty() || sni.len() > 253 || sni.ends_with('.') || sni.parse::<IpAddr>().is_ok() {
        return Err(new_error("sni must be a valid DNS hostname"));
    }

    for label in sni.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(new_error("sni must be a valid DNS hostname"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_sni;

    #[test]
    fn validates_sni_hostname() {
        assert!(validate_sni("example.com").is_ok());
        assert!(validate_sni("edge-1.example.com").is_ok());
        assert!(validate_sni("").is_err());
        assert!(validate_sni("127.0.0.1").is_err());
        assert!(validate_sni("bad_name.example.com").is_err());
        assert!(validate_sni("example.com.").is_err());
    }
}
