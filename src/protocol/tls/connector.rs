use crate::protocol::{Address, DummyUdpStream, ProxyConnector};
use async_trait::async_trait;
use boring::{
    ssl::{SslConnector, SslMethod, SslVersion},
    x509::{store::X509StoreBuilder, X509},
};
use serde::Deserialize;
use std::{fs, io};
use tokio::net::TcpStream;
use tokio_boring::SslStream;

use super::{get_cipher_list, new_error};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanTlsConnectorConfig {
    addr: String,
    sni: String,
    cipher: Option<Vec<String>>,
    cert: Option<String>,
}

pub struct TrojanTlsConnector {
    sni: String,
    server_addr: String,
    tls_connector: SslConnector,
}

impl TrojanTlsConnector {
    pub fn new(config: &TrojanTlsConnectorConfig) -> io::Result<Self> {
        let mut builder = SslConnector::builder(SslMethod::tls()).map_err(new_error)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(new_error)?;
        builder
            .set_alpn_protos(b"\x08http/1.1")
            .map_err(new_error)?;
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
        })
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
}

#[async_trait]
impl ProxyConnector for TrojanTlsConnector {
    type TS = SslStream<TcpStream>;
    type US = DummyUdpStream;

    async fn connect_tcp(&self, _: &Address) -> io::Result<Self::TS> {
        let stream = TcpStream::connect(&self.server_addr).await?;
        stream.set_nodelay(true)?;

        let tls_config = self.tls_connector.configure().map_err(new_error)?;
        let stream = tokio_boring::connect(tls_config, &self.sni, stream)
            .await
            .map_err(new_error)?;

        log::info!("connected to {}", self.server_addr);
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        unimplemented!()
    }
}
