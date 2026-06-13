use crate::protocol::{Address, DummyUdpStream, ProxyConnector, ProxyTcpStream};
use async_trait::async_trait;
use rustls_pki_types::ServerName;
use serde::Deserialize;
use std::{io, path::Path, sync::Arc};
use tokio::net::TcpStream;
use tokio_rustls::{
    client::TlsStream,
    rustls::{
        craft::{CHROME_108, CHROME_112, FIREFOX_105, SAFARI_17_1},
        ClientConfig,
    },
    TlsConnector,
};

use super::{get_cipher_suite, load_cert};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum TlsFingerprint {
    #[serde(rename = "chrome_108")]
    Chrome108,
    #[serde(rename = "chrome_112", alias = "chrome")]
    Chrome112,
    #[serde(rename = "firefox_105", alias = "firefox")]
    Firefox105,
    #[serde(rename = "safari_17_1", alias = "safari")]
    Safari171,
}

impl TlsFingerprint {
    fn apply(self, config: ClientConfig) -> ClientConfig {
        match self {
            Self::Chrome108 => config.with_fingerprint(CHROME_108.builder()),
            Self::Chrome112 => config.with_fingerprint(CHROME_112.builder()),
            Self::Firefox105 => config.with_fingerprint(FIREFOX_105.builder()),
            Self::Safari171 => config.with_fingerprint(SAFARI_17_1.builder()),
        }
    }
}

#[derive(Deserialize)]
pub struct TrojanTlsConnectorConfig {
    addr: String,
    sni: String,
    cipher: Option<Vec<String>>,
    cert: Option<String>,
    #[serde(alias = "utls", alias = "utls_fingerprint")]
    fingerprint: Option<TlsFingerprint>,
}

pub struct TrojanTlsConnector {
    sni: String,
    server_addr: String,
    tls_config: Arc<ClientConfig>,
}

impl ProxyTcpStream for TlsStream<TcpStream> {}

impl TrojanTlsConnector {
    pub fn new(config: &TrojanTlsConnectorConfig) -> io::Result<Self> {
        let cipher_suites = if config.fingerprint.is_some() {
            if config.cipher.is_some() {
                log::warn!("tls cipher configuration is ignored when fingerprint is enabled");
            }
            get_cipher_suite(None)?
        } else {
            get_cipher_suite(config.cipher.clone())?
        };
        let mut provider = tokio_rustls::rustls::crypto::ring::default_provider();
        provider.cipher_suites = cipher_suites;

        let builder = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut root_store = tokio_rustls::rustls::RootCertStore::empty();

        if let Some(ref cert_path) = config.cert {
            let cert_path = Path::new(cert_path);
            let certs = load_cert(cert_path)?;
            for cert in certs {
                root_store.add(cert).unwrap();
            }
        } else {
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }

        let mut tls_config = builder
            .with_root_certificates(root_store)
            .with_no_client_auth();
        if let Some(fingerprint) = config.fingerprint {
            tls_config = fingerprint.apply(tls_config);
            log::debug!("tls fingerprint: {:?}", fingerprint);
        }

        Ok(Self {
            sni: config.sni.clone(),
            server_addr: config.addr.clone(),
            tls_config: Arc::new(tls_config),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{TlsFingerprint, TrojanTlsConnector, TrojanTlsConnectorConfig};

    #[test]
    fn supports_utls_fingerprint_aliases() {
        let cases = [
            ("chrome", TlsFingerprint::Chrome112),
            ("chrome_108", TlsFingerprint::Chrome108),
            ("firefox", TlsFingerprint::Firefox105),
            ("safari", TlsFingerprint::Safari171),
        ];

        for (name, expected) in cases {
            let config: TrojanTlsConnectorConfig = toml::from_str(&format!(
                "addr = \"example.com:443\"\nsni = \"example.com\"\nfingerprint = \"{name}\""
            ))
            .unwrap();
            assert_eq!(config.fingerprint, Some(expected));
            TrojanTlsConnector::new(&config).unwrap();
        }

        let config: TrojanTlsConnectorConfig =
            toml::from_str("addr = \"example.com:443\"\nsni = \"example.com\"\nutls = \"firefox\"")
                .unwrap();
        assert_eq!(config.fingerprint, Some(TlsFingerprint::Firefox105));
    }

    #[test]
    fn rejects_unknown_utls_fingerprint() {
        let result = toml::from_str::<TrojanTlsConnectorConfig>(
            "addr = \"example.com:443\"\nsni = \"example.com\"\nfingerprint = \"edge\"",
        );
        assert!(result.is_err());
    }
}

#[async_trait]
impl ProxyConnector for TrojanTlsConnector {
    type TS = TlsStream<TcpStream>;
    type US = DummyUdpStream;

    async fn connect_tcp(&self, _: &Address) -> io::Result<Self::TS> {
        let stream = TcpStream::connect(&self.server_addr).await?;
        stream.set_nodelay(true)?;

        let dns_name = ServerName::try_from(self.sni.clone())
            .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.to_string()))?
            .to_owned();
        let stream = TlsConnector::from(self.tls_config.clone())
            .connect(dns_name, stream)
            .await?;

        log::info!("connected to {}", self.server_addr);
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        unimplemented!()
    }
}
