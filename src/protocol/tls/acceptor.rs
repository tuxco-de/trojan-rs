use crate::protocol::{
    tls::{default_handshake_timeout_secs, get_cipher_list, new_error, validate_sni},
    AcceptResult, Address, DummyUdpStream, ProxyAcceptor, ProxyTcpStream,
};
use async_trait::async_trait;
use boring::{
    ssl::{
        select_next_proto, AlpnError, NameType, SniError, SslAcceptor, SslAlert, SslFiletype,
        SslMethod, SslVersion,
    },
    x509::X509,
};
use serde::Deserialize;
use std::{fs, io, time::Duration};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_boring::SslStream;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrojanTlsAcceptorConfig {
    addr: String,
    sni: String,
    cert: String,
    key: String,
    cipher: Option<Vec<String>>,
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
}

pub struct TrojanTlsAcceptor {
    tls_acceptor: SslAcceptor,
    tcp_listener: TcpListener,
    handshake_timeout: Duration,
}

impl ProxyTcpStream for SslStream<TcpStream> {}

#[async_trait]
impl ProxyAcceptor for TrojanTlsAcceptor {
    type TS = SslStream<TcpStream>;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (stream, addr) = self.tcp_listener.accept().await?;
        log::info!("tcp connection from {}", addr);
        let stream = timeout(
            self.handshake_timeout,
            tokio_boring::accept(&self.tls_acceptor, stream),
        )
        .await
        .map_err(|_| new_error("TLS handshake timed out"))?
        .map_err(new_error)?;
        Ok(AcceptResult::Tcp((stream, Address::SocketAddress(addr))))
    }
}

impl TrojanTlsAcceptor {
    pub async fn new(config: &TrojanTlsAcceptorConfig) -> io::Result<Self> {
        config.validate()?;
        let tcp_listener = TcpListener::bind(config.addr.to_owned()).await?;
        log::debug!("tls listen addr = {}", config.addr);

        let mut builder =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(new_error)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_2))
            .map_err(new_error)?;
        builder
            .set_certificate_chain_file(&config.cert)
            .map_err(new_error)?;
        builder
            .set_private_key_file(&config.key, SslFiletype::PEM)
            .map_err(new_error)?;
        builder.check_private_key().map_err(new_error)?;

        let certificate_pem = fs::read(&config.cert)?;
        let certificates = X509::stack_from_pem(&certificate_pem).map_err(new_error)?;
        let leaf = certificates
            .first()
            .ok_or_else(|| new_error("certificate file contains no certificates"))?;
        if !leaf.check_host(&config.sni).map_err(new_error)? {
            return Err(new_error(format!(
                "certificate does not match configured sni {}",
                config.sni
            )));
        }
        if let Some(cipher_list) = get_cipher_list(config.cipher.as_deref())? {
            builder
                .set_strict_cipher_list(&cipher_list)
                .map_err(new_error)?;
        }
        builder.set_alpn_select_callback(|_, client| {
            select_next_proto(b"\x08http/1.1", client).ok_or(AlpnError::NOACK)
        });
        let expected_sni = config.sni.clone();
        builder.set_servername_callback(move |ssl, alert| {
            if ssl
                .servername(NameType::HOST_NAME)
                .is_some_and(|name| name.eq_ignore_ascii_case(&expected_sni))
            {
                Ok(())
            } else {
                *alert = SslAlert::UNRECOGNIZED_NAME;
                Err(SniError::ALERT_FATAL)
            }
        });

        let tls_acceptor = builder.build();
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
