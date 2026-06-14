use crate::protocol::{Address, DummyUdpStream, ProxyConnector};
use async_trait::async_trait;
use boring::{
    ssl::{SslConnector, SslMethod, SslVersion},
    x509::{store::X509StoreBuilder, X509},
};
use serde::Deserialize;
use std::{fs, io, time::Duration};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_boring::SslStream;

use super::{default_handshake_timeout_secs, get_cipher_list, new_error, validate_sni, TlsAlpn};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanTlsConnectorConfig {
    addr: String,
    sni: String,
    cipher: Option<Vec<String>>,
    cert: Option<String>,
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
}

pub struct TrojanTlsConnector {
    sni: String,
    server_addr: String,
    tls_connector: SslConnector,
    handshake_timeout: Duration,
}

impl TrojanTlsConnector {
    pub fn new(config: &TrojanTlsConnectorConfig, alpn: TlsAlpn) -> io::Result<Self> {
        config.validate()?;
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(new_error)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(new_error)?;
        if let Some(protocols) = alpn.wire_protocols() {
            builder.set_alpn_protos(protocols).map_err(new_error)?;
        }
        if let Some(cipher_list) = get_cipher_list(config.cipher.as_deref())? {
            builder
                .set_strict_cipher_list(&cipher_list)
                .map_err(new_error)?;
        }

        let mut roots = X509StoreBuilder::new().map_err(new_error)?;
        if let Some(cert_path) = config.cert.as_deref() {
            let pem = fs::read(cert_path)?;
            let certs = X509::stack_from_pem(&pem).map_err(new_error)?;
            if certs.is_empty() {
                return Err(new_error("no certificates found in custom CA file"));
            }
            for cert in certs {
                roots.add_cert(cert).map_err(new_error)?;
            }
        } else {
            for cert in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
                let cert = X509::from_der(cert.as_ref()).map_err(new_error)?;
                roots.add_cert(cert).map_err(new_error)?;
            }
        }
        builder
            .set_verify_cert_store(roots.build())
            .map_err(new_error)?;

        Ok(Self {
            sni: config.sni.clone(),
            server_addr: config.addr.clone(),
            tls_connector: builder.build(),
            handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
        })
    }
}

impl TrojanTlsConnectorConfig {
    fn validate(&self) -> io::Result<()> {
        validate_sni(&self.sni)?;
        if self.handshake_timeout_secs == 0 {
            return Err(new_error("invalid TLS handshake timeout"));
        }
        Ok(())
    }
}

#[async_trait]
impl ProxyConnector for TrojanTlsConnector {
    type TS = SslStream<TcpStream>;
    type US = DummyUdpStream;

    async fn connect_tcp(&self, _: &Address) -> io::Result<Self::TS> {
        let stream = TcpStream::connect(&self.server_addr).await?;
        stream.set_nodelay(true)?;

        let tls_config = self.tls_connector.configure().map_err(new_error)?;
        let stream = timeout(
            self.handshake_timeout,
            tokio_boring::connect(tls_config, &self.sni, stream),
        )
        .await
        .map_err(|_| new_error("TLS handshake timed out"))?
        .map_err(new_error)?;

        log::info!("connected to {}", self.server_addr);
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "unimplemented"))
    }
}

#[cfg(test)]
mod tests {
    use super::TrojanTlsConnectorConfig;

    #[test]
    fn rejects_removed_fingerprint_option() {
        let result = toml::from_str::<TrojanTlsConnectorConfig>(
            "addr = \"example.com:443\"\nsni = \"example.com\"\nfingerprint = \"chrome\"",
        );
        assert!(result.is_err());
    }

    #[test]
    fn uses_default_handshake_timeout() {
        let config: TrojanTlsConnectorConfig =
            toml::from_str("addr = 'example.com:443'\nsni = 'example.com'").unwrap();
        assert_eq!(config.handshake_timeout_secs, 10);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_invalid_sni_and_timeout() {
        let invalid_sni: TrojanTlsConnectorConfig =
            toml::from_str("addr = '127.0.0.1:443'\nsni = '127.0.0.1'").unwrap();
        assert!(invalid_sni.validate().is_err());

        let invalid_timeout: TrojanTlsConnectorConfig = toml::from_str(
            "addr = 'example.com:443'\nsni = 'example.com'\nhandshake_timeout_secs = 0",
        )
        .unwrap();
        assert!(invalid_timeout.validate().is_err());
    }
}
