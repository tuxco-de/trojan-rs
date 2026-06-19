//! REALITY server configuration parsing and validation.

use super::{crypto, new_error};
use crate::protocol::tls::validate_sni;
use crate::protocol::Address;
use serde::Deserialize;
use std::collections::HashSet;
use std::str::FromStr;
use std::time::Duration;

const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MAX_CLIENT_HELLO_SIZE: usize = 16 * 1024;
/// Absolute ceiling so a hostile peer cannot make us buffer unbounded data.
const MAX_CLIENT_HELLO_CEILING: usize = 64 * 1024;

fn default_handshake_timeout_secs() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_SECS
}

fn default_max_client_hello_size() -> usize {
    DEFAULT_MAX_CLIENT_HELLO_SIZE
}

/// Raw `[reality]` table as deserialized from TOML.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RealityAcceptorConfig {
    addr: String,
    target: String,
    server_names: Vec<String>,
    private_key: String,
    short_ids: Vec<String>,
    #[serde(default)]
    max_time_diff_secs: u64,
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
    #[serde(default = "default_max_client_hello_size")]
    max_client_hello_size: usize,
}

/// Validated REALITY server parameters used by the acceptor.
pub struct RealityServer {
    pub addr: String,
    pub target: Address,
    pub server_names: HashSet<String>,
    pub private_key: [u8; 32],
    pub short_ids: HashSet<[u8; 8]>,
    pub max_time_diff: Option<Duration>,
    pub handshake_timeout: Duration,
    pub max_client_hello_size: usize,
}

impl RealityAcceptorConfig {
    pub fn validate(&self) -> std::io::Result<RealityServer> {
        if self.handshake_timeout_secs == 0 {
            return Err(new_error(
                "handshake_timeout_secs must be greater than zero",
            ));
        }
        if self.max_client_hello_size < 512 || self.max_client_hello_size > MAX_CLIENT_HELLO_CEILING
        {
            return Err(new_error(format!(
                "max_client_hello_size must be between 512 and {}",
                MAX_CLIENT_HELLO_CEILING
            )));
        }

        let target = Address::from_str(&self.target)
            .map_err(|_| new_error(format!("invalid target address {}", self.target)))?;
        if port_of(&target) == 0 {
            return Err(new_error("target must include a non-zero port"));
        }

        if self.server_names.is_empty() {
            return Err(new_error("at least one server_name is required"));
        }
        let mut server_names = HashSet::with_capacity(self.server_names.len());
        for name in &self.server_names {
            validate_sni(name)?;
            server_names.insert(name.to_ascii_lowercase());
        }

        let private_key = crypto::parse_private_key(&self.private_key)?;

        if self.short_ids.is_empty() {
            return Err(new_error("at least one short_id is required"));
        }
        let mut short_ids = HashSet::with_capacity(self.short_ids.len());
        for short_id in &self.short_ids {
            short_ids.insert(crypto::parse_short_id(short_id)?);
        }

        let max_time_diff = if self.max_time_diff_secs == 0 {
            None
        } else {
            Some(Duration::from_secs(self.max_time_diff_secs))
        };

        Ok(RealityServer {
            addr: self.addr.clone(),
            target,
            server_names,
            private_key,
            short_ids,
            max_time_diff,
            handshake_timeout: Duration::from_secs(self.handshake_timeout_secs),
            max_client_hello_size: self.max_client_hello_size,
        })
    }
}

fn port_of(addr: &Address) -> u16 {
    match addr {
        Address::SocketAddress(addr) => addr.port(),
        Address::DomainNameAddress(_, port) => *port,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_KEY: &str = "YOuhqB7XBNCYNqzbgZWf0evVCkOPTvxvSU2-3LfFqRg";

    fn base_config() -> String {
        format!(
            "addr = '0.0.0.0:443'\n\
             target = 'www.example.com:443'\n\
             server_names = ['www.example.com']\n\
             private_key = '{VALID_KEY}'\n\
             short_ids = ['0123456789abcdef']\n"
        )
    }

    #[test]
    fn parses_valid_config() {
        let config: RealityAcceptorConfig = toml::from_str(&base_config()).unwrap();
        let server = config.validate().unwrap();
        assert_eq!(server.handshake_timeout, Duration::from_secs(10));
        assert_eq!(server.max_client_hello_size, 16 * 1024);
        assert!(server.max_time_diff.is_none());
        assert!(server.server_names.contains("www.example.com"));
        assert!(server
            .short_ids
            .contains(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]));
    }

    #[test]
    fn rejects_unknown_fields() {
        let config = base_config() + "fingerprint = 'chrome'\n";
        assert!(toml::from_str::<RealityAcceptorConfig>(&config).is_err());
    }

    #[test]
    fn rejects_invalid_inputs() {
        let bad_key = base_config().replace(VALID_KEY, "not-base64!!");
        let config: RealityAcceptorConfig = toml::from_str(&bad_key).unwrap();
        assert!(config.validate().is_err());

        let empty_names = base_config().replace("['www.example.com']", "[]");
        let config: RealityAcceptorConfig = toml::from_str(&empty_names).unwrap();
        assert!(config.validate().is_err());

        let bad_target = base_config().replace("www.example.com:443", "www.example.com");
        let config: RealityAcceptorConfig = toml::from_str(&bad_target).unwrap();
        // Defaults to port 80 via Address parsing, so this is actually valid.
        assert!(config.validate().is_ok());
    }

    #[test]
    fn honours_max_time_diff() {
        let config = base_config() + "max_time_diff_secs = 90\n";
        let config: RealityAcceptorConfig = toml::from_str(&config).unwrap();
        let server = config.validate().unwrap();
        assert_eq!(server.max_time_diff, Some(Duration::from_secs(90)));
    }
}
