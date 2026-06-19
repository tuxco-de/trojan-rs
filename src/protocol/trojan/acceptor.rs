use async_trait::async_trait;
use bytes::Buf;
use serde::Deserialize;
use std::io;

use crate::protocol::fallback::{FallbackConfig, FallbackPage};
use crate::protocol::{trojan::RequestHeader, AcceptResult, ProxyAcceptor};

use super::{new_error, password_to_hash, TrojanUdpStream, HASH_STR_LEN};

#[derive(Deserialize)]
pub struct TrojanAcceptorConfig {
    password: String,
}

pub struct TrojanAcceptor<T: ProxyAcceptor> {
    valid_hash: [u8; HASH_STR_LEN],
    fallback: Option<FallbackPage>,
    inner: T,
}

#[async_trait]
impl<T: ProxyAcceptor> ProxyAcceptor for TrojanAcceptor<T> {
    type TS = T::TS;
    type US = TrojanUdpStream<T::TS>;
    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        loop {
            let (mut stream, addr) = self.inner.accept().await?.unwrap_tcp_with_addr();
            let mut first_packet = Vec::new();
            match RequestHeader::read_from(&mut stream, &self.valid_hash, &mut first_packet).await {
                Ok(header) => match header {
                    RequestHeader::TcpConnect(_, addr) => {
                        log::info!("trojan tcp stream {}", addr);
                        return Ok(AcceptResult::Tcp((stream, addr)));
                    }
                    RequestHeader::UdpAssociate(_) => {
                        log::info!("trojan udp stream {}", addr);
                        return Ok(AcceptResult::Udp(TrojanUdpStream::new(stream)));
                    }
                },
                Err(e) => {
                    log::debug!("first packet {:x?}", first_packet);
                    if let Some(ref fallback) = self.fallback {
                        log::warn!(
                            "invalid trojan request from {}, serving fallback page",
                            addr
                        );
                        fallback.serve(stream, first_packet);
                        continue;
                    }
                    log::warn!(
                        "invalid trojan request from {}, no fallback configured",
                        addr
                    );
                    return Err(new_error(format!("invalid packet: {}", e)));
                }
            }
        }
    }
}

impl<T: ProxyAcceptor> TrojanAcceptor<T> {
    pub fn new(
        config: &TrojanAcceptorConfig,
        fallback_config: Option<&FallbackConfig>,
        inner: T,
    ) -> io::Result<Self> {
        let fallback = FallbackPage::new(fallback_config)?;
        let mut valid_hash = [0u8; HASH_STR_LEN];
        password_to_hash(&config.password)
            .as_bytes()
            .copy_to_slice(&mut valid_hash);
        Ok(Self {
            fallback,
            valid_hash,
            inner,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{Address, DummyUdpStream, ProxyUdpStream, UdpRead};
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
        sync::Mutex,
    };
    use crate::protocol::trojan::password_to_hash;



    struct SingleStreamAcceptor {
        stream: Arc<Mutex<Option<DuplexStream>>>,
    }

    #[async_trait]
    impl ProxyAcceptor for SingleStreamAcceptor {
        type TS = DuplexStream;
        type US = DummyUdpStream;

        async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
            let stream = self
                .stream
                .lock()
                .await
                .take()
                .ok_or(io::ErrorKind::ConnectionAborted)?;
            Ok(AcceptResult::Tcp((stream, Address::new_dummy_address())))
        }
    }

    fn acceptor(server: DuplexStream) -> TrojanAcceptor<SingleStreamAcceptor> {
        let config = TrojanAcceptorConfig {
            password: "password".to_string(),
        };
        TrojanAcceptor::new(
            &config,
            None,
            SingleStreamAcceptor {
                stream: Arc::new(Mutex::new(Some(server))),
            },
        )
        .unwrap()
    }

    fn trojan_request(cmd: u8, port: u16, domain: &str) -> Vec<u8> {
        let hash = password_to_hash("password");
        let mut request = hash.into_bytes();
        request.extend_from_slice(b"\r\n");
        request.push(cmd);
        request.extend_from_slice(&[3, domain.len() as u8]);
        request.extend_from_slice(domain.as_bytes());
        request.extend_from_slice(&[(port >> 8) as u8, port as u8]);
        request.extend_from_slice(b"\r\n");
        request
    }

    #[tokio::test]
    async fn accepts_tcp_request() {
        let (server, mut client) = tokio::io::duplex(4096);
        let acceptor = acceptor(server);

        let client_task = async move {
            let mut req = trojan_request(1, 443, "example.com");
            req.extend_from_slice(b"payload");
            client.write_all(&req).await.unwrap();
        };

        let (accepted, ()) = tokio::join!(acceptor.accept(), client_task);
        let (mut stream, address) = accepted.unwrap().unwrap_tcp_with_addr();
        assert_eq!(address, Address::DomainNameAddress("example.com".into(), 443));
        
        let mut payload = [0u8; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
    }

    #[tokio::test]
    async fn accepts_udp_request() {
        let (server, mut client) = tokio::io::duplex(4096);
        let acceptor = acceptor(server);

        let client_task = async move {
            let mut req = trojan_request(3, 53, "dns.example");
            // Now the UDP packet
            req.extend_from_slice(&[3, 11]); // Address type Domain(3), length 11
            req.extend_from_slice(b"dns.example");
            req.extend_from_slice(&[0, 53]); // Port
            req.extend_from_slice(&[0, 3]); // Length (3)
            req.extend_from_slice(b"\r\n"); // CRLF
            req.extend_from_slice(b"dns"); // Payload
            client.write_all(&req).await.unwrap();
            (client, ())
        };

        let (accepted, (_client, _)) = tokio::join!(acceptor.accept(), client_task);
        let udp = match accepted.unwrap() {
            AcceptResult::Udp(stream) => stream,
            AcceptResult::Tcp(_) => panic!("expected UDP stream"),
        };
        
        // Test UDP stream relay parsing
        let (mut reader, mut _writer) = udp.split();
        let mut packet = [0u8; 32];
        let (length, address) = reader.read_from(&mut packet).await.unwrap();
        assert_eq!(&packet[..length], b"dns");
        assert_eq!(address, Address::DomainNameAddress("dns.example".into(), 53));
    }
}
