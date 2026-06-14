use crate::protocol::{
    tls::{get_cipher_list, new_error},
    AcceptResult, Address, DummyUdpStream, ProxyAcceptor, ProxyTcpStream,
};
use async_trait::async_trait;
use boring::ssl::{select_next_proto, AlpnError, SslAcceptor, SslFiletype, SslMethod, SslVersion};
use serde::Deserialize;
use std::io;
use tokio::net::{TcpListener, TcpStream};
use tokio_boring::SslStream;

#[derive(Deserialize)]
pub struct TrojanTlsAcceptorConfig {
    addr: String,
    cert: String,
    key: String,
    cipher: Option<Vec<String>>,
}

pub struct TrojanTlsAcceptor {
    tls_acceptor: SslAcceptor,
    tcp_listener: TcpListener,
}

impl ProxyTcpStream for SslStream<TcpStream> {}

#[async_trait]
impl ProxyAcceptor for TrojanTlsAcceptor {
    type TS = SslStream<TcpStream>;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (stream, addr) = self.tcp_listener.accept().await?;
        log::info!("tcp connection from {}", addr);
        let stream = tokio_boring::accept(&self.tls_acceptor, stream)
            .await
            .map_err(new_error)?;
        Ok(AcceptResult::Tcp((stream, Address::SocketAddress(addr))))
    }
}

impl TrojanTlsAcceptor {
    pub async fn new(config: &TrojanTlsAcceptorConfig) -> io::Result<Self> {
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
        if let Some(cipher_list) = get_cipher_list(config.cipher.as_deref())? {
            builder
                .set_strict_cipher_list(&cipher_list)
                .map_err(new_error)?;
        }
        builder.set_alpn_select_callback(|_, client| {
            select_next_proto(b"\x08http/1.1", client).ok_or(AlpnError::NOACK)
        });

        let tls_acceptor = builder.build();
        Ok(Self {
            tcp_listener,
            tls_acceptor,
        })
    }
}
