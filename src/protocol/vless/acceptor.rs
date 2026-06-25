use super::{new_error, serve_mux_cool, RequestHeader, VlessTcpStream, VlessUdpStream, VERSION};
use crate::protocol::{AcceptResult, ProxyAcceptor};
use async_trait::async_trait;
use serde::Deserialize;
use std::{io, sync::Arc, time::Duration};
use tokio::io::AsyncWriteExt;
use tokio::sync::{mpsc, Mutex};
use tokio::time::timeout;
use uuid::Uuid;

const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MUX_H2_PROBE_TIMEOUT_SECS: u64 = 1;

fn default_handshake_timeout_secs() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_SECS
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessAcceptorConfig {
    users: Vec<String>,
    multiplex: Option<VlessMultiplexConfig>,
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
}

fn default_mux_enabled() -> bool {
    true
}

fn default_mux_h2_probe_timeout_secs() -> u64 {
    DEFAULT_MUX_H2_PROBE_TIMEOUT_SECS
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VlessMultiplexConfig {
    #[serde(default = "default_mux_enabled")]
    enabled: bool,
    #[serde(default = "default_mux_h2_probe_timeout_secs")]
    h2_probe_timeout_secs: u64,
}

pub struct VlessAcceptor<T: ProxyAcceptor> {
    valid_users: Vec<[u8; 16]>,
    handshake_timeout: Duration,
    mux_accept_tx:
        mpsc::Sender<AcceptResult<VlessTcpStream<T::TS>, VlessUdpStream<VlessTcpStream<T::TS>>>>,
    mux_accept_rx: Arc<
        Mutex<
            mpsc::Receiver<
                AcceptResult<VlessTcpStream<T::TS>, VlessUdpStream<VlessTcpStream<T::TS>>>,
            >,
        >,
    >,
    inner: T,
}

#[async_trait]
impl<T: ProxyAcceptor> ProxyAcceptor for VlessAcceptor<T> {
    type TS = VlessTcpStream<T::TS>;
    type US = VlessUdpStream<VlessTcpStream<T::TS>>;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        loop {
            tokio::select! {
                result = async { self.mux_accept_rx.lock().await.recv().await } => {
                    return result.ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "VLESS mux acceptor closed"));
                }
                result = self.inner.accept() => {
                    let (mut stream, _) = result?.unwrap_tcp_with_addr();
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
                            return Ok(AcceptResult::Tcp((VlessTcpStream::Direct(stream), address)));
                        }
                        RequestHeader::Udp(address) => {
                            log::info!("vless udp stream {}", address);
                            return Ok(AcceptResult::Udp(VlessUdpStream::new(VlessTcpStream::Direct(stream), address)));
                        }
                        RequestHeader::Mux => {
                            log::info!("vless mux.cool stream");
                            let accept_tx = self.mux_accept_tx.clone();
                            tokio::spawn(async move {
                                if let Err(error) = serve_mux_cool(stream, accept_tx).await {
                                    log::debug!("vless mux.cool session ended: {}", error);
                                }
                            });
                        }
                    }
                }
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
        let (mux_accept_tx, mux_accept_rx) = mpsc::channel(128);
        Ok(Self {
            valid_users,
            handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
            mux_accept_tx,
            mux_accept_rx: Arc::new(Mutex::new(mux_accept_rx)),
            inner,
        })
    }
}

impl VlessAcceptorConfig {
    pub fn sing_box_mux_enabled(&self) -> bool {
        self.multiplex
            .as_ref()
            .map_or(true, |multiplex| multiplex.enabled)
    }

    pub fn sing_box_mux_h2_probe_timeout(&self) -> io::Result<Duration> {
        let secs = self
            .multiplex
            .as_ref()
            .map_or(default_mux_h2_probe_timeout_secs(), |multiplex| {
                multiplex.h2_probe_timeout_secs
            });
        if secs == 0 {
            return Err(new_error("mux h2 probe timeout must be greater than zero"));
        }
        Ok(Duration::from_secs(secs))
    }
}

#[cfg(test)]
mod tests {
    use super::{VlessAcceptor, VlessAcceptorConfig};
    use crate::protocol::vless::VlessUdpStream;
    use crate::protocol::websocket::acceptor::{WebSocketAcceptor, WebSocketAcceptorConfig};
    use crate::protocol::{
        AcceptResult, Address, DummyUdpStream, ProxyAcceptor, ProxyUdpStream, UdpRead, UdpWrite,
    };
    use async_trait::async_trait;
    use base64::{engine::general_purpose, Engine as _};
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use std::{future::pending, io, sync::Arc, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
        sync::Mutex,
    };
    use tokio_tungstenite::{
        client_async,
        tungstenite::{client::IntoClientRequest, Message},
    };
    use uuid::Uuid;

    struct SingleStreamAcceptor {
        stream: Arc<Mutex<Option<DuplexStream>>>,
    }

    #[async_trait]
    impl ProxyAcceptor for SingleStreamAcceptor {
        type TS = DuplexStream;
        type US = DummyUdpStream;

        async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
            loop {
                if let Some(stream) = self.stream.lock().await.take() {
                    return Ok(AcceptResult::Tcp((stream, Address::new_dummy_address())));
                }
                pending::<()>().await;
            }
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
    async fn accepts_xray_style_websocket_early_data() {
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
            let mut bytes = request(1, 443, "example.com");
            bytes.extend_from_slice(b"payload");
            let early_data = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            let mut request = "ws://example.com/vless?ed=2560"
                .into_client_request()
                .unwrap();
            request.headers_mut().insert(
                "Sec-WebSocket-Protocol",
                early_data.as_str().parse().unwrap(),
            );
            let (mut websocket, _) = client_async(request, client).await.unwrap();
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
    async fn accepts_path_style_websocket_early_data() {
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
            let mut bytes = request(1, 443, "example.com");
            bytes.extend_from_slice(b"payload");
            let early_data = general_purpose::URL_SAFE_NO_PAD.encode(bytes);
            let url = format!("ws://example.com/vless/{}?ed=2560", early_data);
            let (mut websocket, _) = client_async(url, client).await.unwrap();
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
    async fn accepts_native_vless_mux_cool_tcp_stream() {
        let (server, mut client) = tokio::io::duplex(4096);
        let acceptor = acceptor(server);
        let client_task = async move {
            let mut bytes = request(3, 0, "");
            bytes.truncate(18);
            bytes.push(3);
            client.write_all(&bytes).await.unwrap();

            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0, 0]);

            let mut metadata = vec![0, 1, 1, 1, 1];
            metadata.extend_from_slice(&443u16.to_be_bytes());
            metadata.extend_from_slice(&[2, 11]);
            metadata.extend_from_slice(b"example.com");
            client
                .write_all(&(metadata.len() as u16).to_be_bytes())
                .await
                .unwrap();
            client.write_all(&metadata).await.unwrap();
            client.write_all(&7u16.to_be_bytes()).await.unwrap();
            client.write_all(b"payload").await.unwrap();

            let meta_len = client.read_u16().await.unwrap();
            assert_eq!(meta_len, 4);
            let session_id = client.read_u16().await.unwrap();
            let status = client.read_u8().await.unwrap();
            let option = client.read_u8().await.unwrap();
            assert_eq!((session_id, status, option), (1, 2, 1));
            let data_len = client.read_u16().await.unwrap() as usize;
            let mut reply = vec![0u8; data_len];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
        };

        tokio::join!(
            async {
                let (mut stream, address) = acceptor.accept().await.unwrap().unwrap_tcp_with_addr();
                assert_eq!(
                    address,
                    Address::DomainNameAddress("example.com".into(), 443)
                );
                let mut payload = [0u8; 7];
                stream.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"payload");
                stream.write_all(b"reply").await.unwrap();
                stream.flush().await.unwrap();
            },
            client_task
        );
    }

    #[tokio::test]
    async fn accepts_native_vless_mux_cool_udp_stream() {
        let (server, mut client) = tokio::io::duplex(4096);
        let acceptor = acceptor(server);
        let client_task = async move {
            let mut bytes = request(3, 0, "");
            bytes.truncate(18);
            bytes.push(3);
            client.write_all(&bytes).await.unwrap();

            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [0, 0]);

            let mut metadata = vec![0, 1, 1, 1, 2];
            metadata.extend_from_slice(&53u16.to_be_bytes());
            metadata.extend_from_slice(&[2, 11]);
            metadata.extend_from_slice(b"dns.example");
            client
                .write_all(&(metadata.len() as u16).to_be_bytes())
                .await
                .unwrap();
            client.write_all(&metadata).await.unwrap();
            client.write_all(&3u16.to_be_bytes()).await.unwrap();
            client.write_all(b"dns").await.unwrap();

            let meta_len = client.read_u16().await.unwrap() as usize;
            let mut reply_metadata = vec![0u8; meta_len];
            client.read_exact(&mut reply_metadata).await.unwrap();
            assert_eq!(&reply_metadata[..5], &[0, 1, 2, 1, 2]);
            assert_eq!(&reply_metadata[5..7], &53u16.to_be_bytes());
            assert_eq!(&reply_metadata[7..9], &[2, 11]);
            assert_eq!(&reply_metadata[9..], b"dns.example");
            let data_len = client.read_u16().await.unwrap() as usize;
            let mut reply = vec![0u8; data_len];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"reply");
        };

        tokio::join!(
            async {
                let udp = match acceptor.accept().await.unwrap() {
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
            },
            client_task
        );
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

    #[tokio::test]
    async fn accepts_zero_length_udp_packets() {
        let (server, mut client) = tokio::io::duplex(4096);
        let acceptor = acceptor(server);
        let client_task = async move {
            let mut bytes = request(2, 53, "dns.example");
            bytes.extend_from_slice(&[0, 0]);
            client.write_all(&bytes).await.unwrap();
            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            response
        };

        let (accepted, response) = tokio::join!(acceptor.accept(), client_task);
        assert_eq!(response, [0, 0]);
        let udp = match accepted.unwrap() {
            AcceptResult::Udp(stream) => stream,
            AcceptResult::Tcp(_) => panic!("expected UDP stream"),
        };
        let (mut reader, writer) = udp.split();
        let mut packet = [0u8; 32];
        let (length, address) = reader.read_from(&mut packet).await.unwrap();
        assert_eq!(length, 0);
        assert_eq!(
            address,
            Address::DomainNameAddress("dns.example".into(), 53)
        );

        let _ = VlessUdpStream::reunite(reader, writer).close().await;
    }

    #[test]
    fn multiplex_defaults_to_auto() {
        let config: VlessAcceptorConfig =
            toml::from_str("users = ['d342d11e-d424-4583-b36e-524ab1f0afa4']").unwrap();
        assert!(config.sing_box_mux_enabled());

        let config: VlessAcceptorConfig = toml::from_str(
            "users = ['d342d11e-d424-4583-b36e-524ab1f0afa4']\n[multiplex]\nh2_probe_timeout_secs = 3\n",
        )
        .unwrap();
        assert!(config.sing_box_mux_enabled());
        assert_eq!(
            config.sing_box_mux_h2_probe_timeout().unwrap(),
            Duration::from_secs(3)
        );

        let config: VlessAcceptorConfig = toml::from_str(
            "users = ['d342d11e-d424-4583-b36e-524ab1f0afa4']\n[multiplex]\nenabled = false\n",
        )
        .unwrap();
        assert!(!config.sing_box_mux_enabled());
    }

    #[test]
    fn rejects_zero_mux_probe_timeout() {
        let config: VlessAcceptorConfig = toml::from_str(
            "users = ['d342d11e-d424-4583-b36e-524ab1f0afa4']\n[multiplex]\nh2_probe_timeout_secs = 0\n",
        )
        .unwrap();
        assert!(config.sing_box_mux_h2_probe_timeout().is_err());
    }

    #[test]
    fn rejects_unknown_vless_config_fields() {
        let result = toml::from_str::<VlessAcceptorConfig>(
            "users = ['d342d11e-d424-4583-b36e-524ab1f0afa4']\nunknown = true\n",
        );
        assert!(matches!(result, Err(error) if error.to_string().contains("unknown field")));
    }
}
