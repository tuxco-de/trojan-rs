use crate::error::Error;
use std::{io, net::IpAddr};

pub mod acceptor;
pub mod connector;

const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

pub(super) fn default_handshake_timeout_secs() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_SECS
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TlsAlpn {
    None,
    Http11,
}

impl TlsAlpn {
    pub(super) fn wire_protocols(self) -> Option<&'static [u8]> {
        match self {
            Self::None => None,
            Self::Http11 => Some(b"\x08http/1.1"),
        }
    }
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

pub fn get_cipher_list(cipher: Option<&[String]>) -> io::Result<Option<String>> {
    let Some(cipher) = cipher else {
        return Ok(None);
    };
    if cipher.is_empty() {
        return Err(new_error("cipher list cannot be empty"));
    }

    cipher
        .iter()
        .map(|name| {
            let openssl_name = match name.as_str() {
                "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-ECDSA-CHACHA20-POLY1305",
                "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => "ECDHE-RSA-CHACHA20-POLY1305",
                "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => "ECDHE-ECDSA-AES256-GCM-SHA384",
                "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => "ECDHE-ECDSA-AES128-GCM-SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => "ECDHE-RSA-AES256-GCM-SHA384",
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => "ECDHE-RSA-AES128-GCM-SHA256",
                name if name.starts_with("TLS13_") => {
                    return Err(new_error(
                        "BoringSSL does not expose TLS 1.3 cipher suite configuration",
                    ));
                }
                _ => return Err(new_error(format!("bad cipher: {name}"))),
            };
            Ok(openssl_name)
        })
        .collect::<io::Result<Vec<_>>>()
        .map(|names| Some(names.join(":")))
}

#[cfg(test)]
mod tests {
    use super::{get_cipher_list, validate_sni, TlsAlpn};

    #[test]
    fn translates_tls12_cipher_names() {
        let ciphers = vec![
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256".to_owned(),
            "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256".to_owned(),
        ];
        assert_eq!(
            get_cipher_list(Some(&ciphers)).unwrap().as_deref(),
            Some("ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305")
        );
    }

    #[test]
    fn rejects_tls13_cipher_configuration() {
        let ciphers = vec!["TLS13_AES_128_GCM_SHA256".to_owned()];
        assert!(get_cipher_list(Some(&ciphers)).is_err());
    }

    #[test]
    fn validates_sni_hostname() {
        assert!(validate_sni("example.com").is_ok());
        assert!(validate_sni("edge-1.example.com").is_ok());
        assert!(validate_sni("").is_err());
        assert!(validate_sni("127.0.0.1").is_err());
        assert!(validate_sni("bad_name.example.com").is_err());
        assert!(validate_sni("example.com.").is_err());
    }

    #[test]
    fn exposes_alpn_only_for_http_transport() {
        assert_eq!(TlsAlpn::None.wire_protocols(), None);
        assert_eq!(TlsAlpn::Http11.wire_protocols(), Some(&b"\x08http/1.1"[..]));
    }
}
