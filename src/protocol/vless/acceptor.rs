use super::{new_error, RequestHeader, VlessUdpStream, VERSION};
use crate::protocol::{AcceptResult, ProxyAcceptor};
use async_trait::async_trait;
use serde::Deserialize;
use std::{io, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use uuid::Uuid;

const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

fn default_handshake_timeout_secs() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_SECS
}

#[derive(Deserialize)]
pub struct VlessAcceptorConfig {
    users: Vec<String>,
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
}

pub struct VlessAcceptor<T: ProxyAcceptor> {
    valid_users: Vec<[u8; 16]>,
    handshake_timeout: Duration,
    inner: T,
}

#[async_trait]
impl<T: ProxyAcceptor> ProxyAcceptor for VlessAcceptor<T> {
    type TS = T::TS;
    type US = VlessUdpStream<T::TS>;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        let (mut stream, _) = self.inner.accept().await?.unwrap_tcp_with_addr();
        let header = timeout(
            self.handshake_timeout,
            RequestHeader::read_from(&mut stream, &self.valid_users),
        )
        .await
        .map_err(|_| new_error("request header timed out"))??;
        stream.write_all(&[VERSION, 0]).await?;
        stream.flush().await?;

        match header {
            RequestHeader::Tcp(address) => {
                log::info!("vless tcp stream {}", address);
                Ok(AcceptResult::Tcp((stream, address)))
            }
            RequestHeader::Udp(address) => {
                log::info!("vless udp stream {}", address);
                Ok(AcceptResult::Udp(VlessUdpStream::new(stream, address)))
            }
        }
    }
}

impl<T: ProxyAcceptor> VlessAcceptor<T> {
    pub fn new(config: &VlessAcceptorConfig, inner: T) -> io::Result<Self> {
        if config.users.is_empty() {
            return Err(new_error("at least one VLESS user is required"));
        }
        if config.handshake_timeout_secs == 0 {
            return Err(new_error("handshake timeout must be greater than zero"));
        }
        let mut valid_users = Vec::with_capacity(config.users.len());
        for user in &config.users {
            let id = Uuid::parse_str(user)
                .map_err(|error| new_error(format!("invalid user UUID {}: {}", user, error)))?;
            let bytes = *id.as_bytes();
            if valid_users.contains(&bytes) {
                return Err(new_error(format!("duplicate user UUID {}", user)));
            }
            valid_users.push(bytes);
        }
        Ok(Self {
            valid_users,
            handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
            inner,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{VlessAcceptor, VlessAcceptorConfig};
    use crate::protocol::vless::VlessUdpStream;
    use crate::protocol::websocket::acceptor::{WebSocketAcceptor, WebSocketAcceptorConfig};
    use crate::protocol::{
        AcceptResult, Address, DummyUdpStream, ProxyAcceptor, ProxyUdpStream,
        UdpRead, UdpWrite,
    };
    use async_trait::async_trait;
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use std::{io, sync::Arc};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
        sync::Mutex,
    };
    use tokio_tungstenite::{client_async, tungstenite::Message};
    use uuid::Uuid;



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

    fn request(command: u8, port: u16, domain: &str) -> Vec<u8> {
        let user = Uuid::parse_str("d342d11e-d424-4583-b36e-524ab1f0afa4").unwrap();
        let mut request = vec![0];
        request.extend_from_slice(user.as_bytes());
        request.extend_from_slice(&[
            0,
            command,
            (port >> 8) as u8,
            port as u8,
            2,
            domain.len() as u8,
        ]);
        request.extend_from_slice(domain.as_bytes());
        request
    }

    fn acceptor(server: DuplexStream) -> VlessAcceptor<SingleStreamAcceptor> {
        let config: VlessAcceptorConfig =
            toml::from_str("users = ['d342d11e-d424-4583-b36e-524ab1f0afa4']").unwrap();
        VlessAcceptor::new(
            &config,
            SingleStreamAcceptor {
                stream: Arc::new(Mutex::new(Some(server))),
            },
        )
        .unwrap()
    }

    #[tokio::test]
    async fn accepts_tcp_and_sends_response_header() {
        let (server, mut client) = tokio::io::duplex(4096);
        let acceptor = acceptor(server);
        let client_task = async move {
            let mut bytes = request(1, 443, "example.com");
            bytes.extend_from_slice(b"payload");
            client.write_all(&bytes).await.unwrap();
            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            (client, response)
        };

        let (accepted, (_, response)) = tokio::join!(acceptor.accept(), client_task);
        assert_eq!(response, [0, 0]);
        let (mut stream, address) = accepted.unwrap().unwrap_tcp_with_addr();
        assert_eq!(
            address,
            Address::DomainNameAddress("example.com".into(), 443)
        );
        let mut payload = [0u8; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
    }

    #[tokio::test]
    async fn accepts_vless_request_over_websocket() {
        let (server, client) = tokio::io::duplex(16 * 1024);
        let websocket_config: WebSocketAcceptorConfig = toml::from_str("path = '/vless'").unwrap();
        let websocket = WebSocketAcceptor::new_strict(
            &websocket_config,
            None,
            SingleStreamAcceptor {
                stream: Arc::new(Mutex::new(Some(server))),
            },
        )
        .unwrap();
        let config: VlessAcceptorConfig =
            toml::from_str("users = ['d342d11e-d424-4583-b36e-524ab1f0afa4']").unwrap();
        let acceptor = VlessAcceptor::new(&config, websocket).unwrap();

        let client_task = async move {
            let (mut websocket, _) = client_async("ws://example.com/vless", client)
                .await
                .unwrap();
            let mut bytes = request(1, 443, "example.com");
            bytes.extend_from_slice(b"payload");
            websocket
                .send(Message::Binary(Bytes::from(bytes)))
                .await
                .unwrap();
            match websocket.next().await {
                Some(Ok(Message::Binary(response))) => assert_eq!(&response[..], &[0, 0]),
                response => panic!("unexpected VLESS response: {:?}", response),
            }
        };

        let (accepted, ()) = tokio::join!(acceptor.accept(), client_task);
        let (mut stream, address) = accepted.unwrap().unwrap_tcp_with_addr();
        assert_eq!(
            address,
            Address::DomainNameAddress("example.com".into(), 443)
        );
        let mut payload = [0u8; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
    }

    #[tokio::test]
    async fn relays_length_prefixed_udp_packets() {
        let (server, mut client) = tokio::io::duplex(4096);
        let acceptor = acceptor(server);
        let client_task = async move {
            let mut bytes = request(2, 53, "dns.example");
            bytes.extend_from_slice(&[0, 3]);
            bytes.extend_from_slice(b"dns");
            client.write_all(&bytes).await.unwrap();
            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            (client, response)
        };

        let (accepted, (mut client, response)) = tokio::join!(acceptor.accept(), client_task);
        assert_eq!(response, [0, 0]);
        let udp = match accepted.unwrap() {
            AcceptResult::Udp(stream) => stream,
            AcceptResult::Tcp(_) => panic!("expected UDP stream"),
        };
        let (mut reader, mut writer) = udp.split();
        let mut packet = [0u8; 32];
        let (length, address) = reader.read_from(&mut packet).await.unwrap();
        assert_eq!(&packet[..length], b"dns");
        assert_eq!(
            address,
            Address::DomainNameAddress("dns.example".into(), 53)
        );

        writer.write_to(b"reply", &address).await.unwrap();
        let mut reply = [0u8; 7];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"\0\x05reply");

        let _ = VlessUdpStream::reunite(reader, writer).close().await;
    }
}
