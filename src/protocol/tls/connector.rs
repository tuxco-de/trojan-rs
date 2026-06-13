use crate::protocol::{Address, DummyUdpStream, ProxyConnector, ProxyTcpStream};
use async_trait::async_trait;
use serde::Deserialize;
use std::{
    io,
    path::Path,
    sync::Arc,
};
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, rustls::ClientConfig, TlsConnector};
use rustls_pki_types::ServerName;

use super::{get_cipher_suite, load_cert};

#[derive(Deserialize)]
pub struct TrojanTlsConnectorConfig {
    addr: String,
    sni: String,
    cipher: Option<Vec<String>>,
    cert: Option<String>,
}

pub struct TrojanTlsConnector {
    sni: String,
    server_addr: String,
    tls_config: Arc<ClientConfig>,
}

impl ProxyTcpStream for TlsStream<TcpStream> {}

impl TrojanTlsConnector {
    pub fn new(config: &TrojanTlsConnectorConfig) -> io::Result<Self> {
        let cipher_suites = get_cipher_suite(config.cipher.clone())?;
        let mut provider = tokio_rustls::rustls::crypto::ring::default_provider();
        provider.cipher_suites = cipher_suites;

        let builder = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

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

        let tls_config = builder
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(Self {
            sni: config.sni.clone(),
            server_addr: config.addr.clone(),
            tls_config: Arc::new(tls_config),
        })
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
