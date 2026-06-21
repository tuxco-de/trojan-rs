use crate::protocol::{
    fallback::{FallbackConfig, FallbackPage},
    tls::{default_handshake_timeout_secs, new_error, validate_sni},
    AcceptResult, Address, DummyUdpStream, ProxyAcceptor, ProxyTcpStream,
};
use async_trait::async_trait;
use rustls::{server::ResolvesServerCertUsingSni, sign::CertifiedKey, ServerConfig};
use rustls_pki_types::CertificateDer;
use serde::Deserialize;
use std::{
    fs::File,
    io::{self, BufReader},
    sync::Arc,
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanTlsAcceptorConfig {
    addr: String,
    sni: String,
    cert: String,
    key: String,
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
}

pub struct TrojanTlsAcceptor {
    tls_acceptor: TlsAcceptor,
    tcp_listener: TcpListener,
    handshake_timeout: Duration,
}

impl ProxyTcpStream for TlsStream<TcpStream> {}

pub trait NegotiatedAlpn {
    fn negotiated_alpn(&self) -> Option<&[u8]>;
}

impl NegotiatedAlpn for TlsStream<TcpStream> {
    fn negotiated_alpn(&self) -> Option<&[u8]> {
        self.get_ref().1.alpn_protocol()
    }
}

pub struct AlpnFallbackAcceptor<T: ProxyAcceptor> {
    fallback: Option<FallbackPage>,
    inner: T,
}

impl<T: ProxyAcceptor> AlpnFallbackAcceptor<T> {
    pub fn new(fallback_config: Option<&FallbackConfig>, inner: T) -> io::Result<Self> {
        Ok(Self {
            fallback: FallbackPage::new(fallback_config)?,
            inner,
        })
    }
}

#[async_trait]
impl<T> ProxyAcceptor for AlpnFallbackAcceptor<T>
where
    T: ProxyAcceptor,
    T::TS: NegotiatedAlpn,
{
    type TS = T::TS;
    type US = T::US;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        loop {
            match self.inner.accept().await? {
                AcceptResult::Tcp((mut stream, _addr))
                    if stream.negotiated_alpn() == Some(b"h2") =>
                {
                    if let Some(fallback) = &self.fallback {
                        fallback.serve_h2(stream);
                    } else {
                        let _ = stream.shutdown().await;
                    }
                }
                result => return Ok(result),
            }
        }
    }
}

#[async_trait]
impl ProxyAcceptor for TrojanTlsAcceptor {
    type TS = TlsStream<TcpStream>;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (stream, addr) = self.tcp_listener.accept().await?;
        log::info!("tcp connection from {}", addr);
        if let Err(e) = stream.set_nodelay(true) {
            log::debug!("failed to enable TCP_NODELAY for inbound {}: {}", addr, e);
        }
        let stream = timeout(self.handshake_timeout, self.tls_acceptor.accept(stream))
            .await
            .map_err(|_| new_error("TLS handshake timed out"))?
            .map_err(new_error)?;
        Ok(AcceptResult::Tcp((stream, Address::SocketAddress(addr))))
    }
}

impl TrojanTlsAcceptor {
    pub async fn new(
        config: &TrojanTlsAcceptorConfig,
        enable_http2_fallback: bool,
    ) -> io::Result<Self> {
        config.validate()?;
        let tcp_listener = TcpListener::bind(config.addr.to_owned()).await?;
        log::debug!("tls listen addr = {}", config.addr);

        let cert_file = &mut BufReader::new(File::open(&config.cert).map_err(new_error)?);

        let certs: Vec<CertificateDer> = rustls_pemfile::certs(cert_file)
            .collect::<Result<Vec<_>, _>>()
            .map_err(new_error)?;

        let key_file = &mut BufReader::new(File::open(&config.key).map_err(new_error)?);
        let key = rustls_pemfile::private_key(key_file)
            .map_err(new_error)?
            .ok_or_else(|| new_error("no private key found"))?;

        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let certified_key = CertifiedKey::from_der(certs, key, &provider)
            .map_err(|e| new_error(format!("invalid TLS certificate/key: {e}")))?;
        let mut resolver = ResolvesServerCertUsingSni::new();
        resolver
            .add(&config.sni, certified_key)
            .map_err(|e| new_error(format!("certificate does not match configured sni: {e}")))?;

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(std::sync::Arc::new(resolver));

        server_config.alpn_protocols = if enable_http2_fallback {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        } else {
            vec![b"http/1.1".to_vec()]
        };

        let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));
        Ok(Self {
            tcp_listener,
            tls_acceptor,
            handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
        })
    }
}

impl TrojanTlsAcceptorConfig {
    fn validate(&self) -> io::Result<()> {
        validate_sni(&self.sni)?;
        if self.handshake_timeout_secs == 0 {
            return Err(new_error("invalid TLS handshake timeout"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::TrojanTlsAcceptorConfig;

    #[test]
    fn parses_sni_and_default_handshake_timeout() {
        let config: TrojanTlsAcceptorConfig = toml::from_str(
            "addr = '0.0.0.0:443'\nsni = 'example.com'\ncert = 'cert.pem'\nkey = 'key.pem'",
        )
        .unwrap();
        assert_eq!(config.handshake_timeout_secs, 10);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_unknown_tls_options() {
        let result = toml::from_str::<TrojanTlsAcceptorConfig>(
            "addr = '0.0.0.0:443'\nsni = 'example.com'\ncert = 'cert.pem'\nkey = 'key.pem'\nfingerprint = 'chrome'",
        );
        assert!(result.is_err());
    }
}
