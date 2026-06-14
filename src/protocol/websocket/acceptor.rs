use super::{
    default_handshake_timeout_secs, default_max_handshake_size, new_error, BinaryWsStream,
    WebSocketOptions,
};
use crate::protocol::fallback::{FallbackConfig, FallbackPage};
use crate::protocol::{AcceptResult, DummyUdpStream, ProxyAcceptor, ProxyTcpStream};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use log::error;
use serde::Deserialize;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::{timeout_at, Instant};
use tokio_tungstenite::{
    accept_hdr_async_with_config,
    tungstenite::{
        handshake::server::{Callback, ErrorResponse, Request, Response},
        http::StatusCode,
        protocol::WebSocketConfig,
    },
};

#[derive(Deserialize)]
pub struct WebSocketAcceptorConfig {
    path: String,
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
    #[serde(default = "default_max_handshake_size")]
    max_handshake_size: usize,
    #[serde(flatten)]
    options: WebSocketOptions,
}

struct WebSocketCallback {
    path: Arc<str>,
}

impl Callback for WebSocketCallback {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        let date_str = httpdate::fmt_http_date(std::time::SystemTime::now());
        
        if request.uri().path() != self.path.as_ref() {
            let mut resp = ErrorResponse::new(None);
            *resp.status_mut() = StatusCode::NOT_FOUND;
            
            if let Ok(val) = "nginx".parse() {
                resp.headers_mut().insert("Server", val);
            }
            if let Ok(val) = date_str.parse() {
                resp.headers_mut().insert("Date", val);
            }
            if let Ok(val) = "close".parse() {
                resp.headers_mut().insert("Connection", val);
            }

            error!(
                "invalid websocket path: {}, expected: {}",
                request.uri(),
                self.path
            );
            Err(resp)
        } else {
            let mut response = response;
            if let Ok(val) = "nginx".parse() {
                response.headers_mut().insert("Server", val);
            }
            if let Ok(val) = date_str.parse() {
                response.headers_mut().insert("Date", val);
            }
            Ok(response)
        }
    }
}

pub enum TrojanGoWebSocketStream<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    Raw(PrefixedStream<T>),
    WebSocket(Box<BinaryWsStream<PrefixedStream<T>>>),
}

impl<T> ProxyTcpStream for TrojanGoWebSocketStream<T> where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin
{
}

impl<T> AsyncRead for TrojanGoWebSocketStream<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::WebSocket(stream) => Pin::new(stream.as_mut()).poll_read(cx, buf),
        }
    }
}

impl<T> AsyncWrite for TrojanGoWebSocketStream<T>
where
    T: AsyncRead + AsyncWrite + Send + Sync + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::WebSocket(stream) => Pin::new(stream.as_mut()).poll_write(cx, buf),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_flush(cx),
            Self::WebSocket(stream) => Pin::new(stream.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Raw(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::WebSocket(stream) => Pin::new(stream.as_mut()).poll_shutdown(cx),
        }
    }
}

pub struct PrefixedStream<T> {
    prefix: Bytes,
    inner: T,
}

impl<T> PrefixedStream<T> {
    fn new(prefix: Vec<u8>, inner: T) -> Self {
        Self {
            prefix: Bytes::from(prefix),
            inner,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for PrefixedStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let len = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..len]);
            self.prefix.advance(len);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub struct WebSocketAcceptor<T: ProxyAcceptor> {
    path: Arc<str>,
    handshake_timeout: Duration,
    max_handshake_size: usize,
    websocket_config: WebSocketConfig,
    allow_raw: bool,
    fallback: Option<FallbackPage>,
    inner: T,
}

#[async_trait]
impl<T: ProxyAcceptor> ProxyAcceptor for WebSocketAcceptor<T> {
    type TS = TrojanGoWebSocketStream<T::TS>;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        loop {
            let (mut stream, addr) = self.inner.accept().await?.unwrap_tcp_with_addr();
            let deadline = Instant::now() + self.handshake_timeout;
            let request_head = timeout_at(
                deadline,
                read_request_head(&mut stream, self.max_handshake_size),
            )
            .await
            .map_err(|_| new_error("websocket handshake timed out"))??;

            let is_websocket = is_trojan_go_websocket_request(&request_head, self.path.as_ref());
            if !is_websocket {
                if !self.allow_raw {
                    if let Some(ref fallback) = self.fallback {
                        log::info!("serving fallback page to {}", addr);
                        fallback.serve(stream, request_head);
                        continue;
                    }
                    return Err(new_error("websocket upgrade required"));
                }
                let prefixed = PrefixedStream::new(request_head, stream);
                return Ok(AcceptResult::Tcp((
                    TrojanGoWebSocketStream::Raw(prefixed),
                    addr,
                )));
            }

            let prefixed = PrefixedStream::new(request_head, stream);
            let stream = timeout_at(
                deadline,
                accept_hdr_async_with_config(
                    prefixed,
                    WebSocketCallback {
                        path: Arc::clone(&self.path),
                    },
                    Some(self.websocket_config),
                ),
            )
            .await
            .map_err(|_| new_error("websocket handshake timed out"))?
            .map_err(new_error)?;
            return Ok(AcceptResult::Tcp((
                TrojanGoWebSocketStream::WebSocket(Box::new(BinaryWsStream::new(stream))),
                addr,
            )));
        }
    }
}

impl<T: ProxyAcceptor> WebSocketAcceptor<T> {
    pub fn new(
        config: &WebSocketAcceptorConfig,
        fallback_config: Option<&FallbackConfig>,
        inner: T,
    ) -> io::Result<Self> {
        Self::new_inner(config, fallback_config, inner, true)
    }

    pub fn new_strict(
        config: &WebSocketAcceptorConfig,
        fallback_config: Option<&FallbackConfig>,
        inner: T,
    ) -> io::Result<Self> {
        Self::new_inner(config, fallback_config, inner, false)
    }

    fn new_inner(
        config: &WebSocketAcceptorConfig,
        fallback_config: Option<&FallbackConfig>,
        inner: T,
        allow_raw: bool,
    ) -> io::Result<Self> {
        validate_config(config)?;
        let fallback = FallbackPage::new(fallback_config)?;
        let websocket_config = config.options.tungstenite_config();
        Ok(Self {
            inner,
            path: Arc::from(config.path.as_str()),
            handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
            max_handshake_size: config.max_handshake_size,
            websocket_config,
            allow_raw,
            fallback,
        })
    }
}

fn validate_config(config: &WebSocketAcceptorConfig) -> io::Result<()> {
    if !config.path.starts_with('/') {
        return Err(new_error("websocket path must start with '/'"));
    }
    if config.path.contains('?') || config.path.contains('#') {
        return Err(new_error(
            "websocket path must not contain a query or fragment",
        ));
    }
    if config.handshake_timeout_secs == 0 || config.max_handshake_size < 256 {
        return Err(new_error("invalid websocket handshake limits"));
    }
    config.options.validate()
}

async fn read_request_head<T: AsyncRead + Unpin>(
    stream: &mut T,
    max_size: usize,
) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(1024);
    let mut first = [0u8; 4];
    stream.read_exact(&mut first).await?;
    head.extend_from_slice(&first);

    if &first != b"GET " {
        return Ok(head);
    }

    while find_header_end(&head).is_none() {
        if head.len() >= max_size {
            return Err(new_error("websocket handshake headers are too large"));
        }
        let remaining = (max_size - head.len()).min(1024);
        let mut buffer = [0u8; 1024];
        let read = stream.read(&mut buffer[..remaining]).await?;
        if read == 0 {
            return Ok(head);
        }
        head.extend_from_slice(&buffer[..read]);
    }
    Ok(head)
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|i| i + 4)
}

fn is_trojan_go_websocket_request(request: &[u8], expected_path: &str) -> bool {
    let Some(header_end) = find_header_end(request) else {
        return false;
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    if !matches!(
        parsed.parse(&request[..header_end]),
        Ok(httparse::Status::Complete(_))
    ) {
        return false;
    }
    if parsed.method != Some("GET") {
        return false;
    }
    let path_matches = parsed
        .path
        .is_some_and(|path| path.split_once('?').map_or(path, |(path, _)| path) == expected_path);
    let has_upgrade = parsed.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("upgrade")
            && std::str::from_utf8(header.value)
                .map(|value| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("websocket"))
                })
                .unwrap_or(false)
    });
    path_matches && has_upgrade
}

#[cfg(test)]
mod tests {
    use super::{
        is_trojan_go_websocket_request, read_request_head, BinaryWsStream, PrefixedStream,
        WebSocketAcceptorConfig, WebSocketCallback,
    };
    use futures_util::SinkExt;
    use std::sync::Arc;
    use tokio::io::AsyncReadExt;
    use tokio_tungstenite::{
        accept_hdr_async_with_config, client_async,
        tungstenite::{protocol::WebSocketConfig, Message},
    };

    #[test]
    fn recognizes_trojan_go_websocket_handshake() {
        let request = b"GET /trojan?ed=2048 HTTP/1.1\r\nHost: example.com\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\n\r\n";
        assert!(is_trojan_go_websocket_request(request, "/trojan"));
    }

    #[test]
    fn routes_other_http_paths_to_trojan_fallback() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
        assert!(!is_trojan_go_websocket_request(request, "/trojan"));
    }

    #[test]
    fn legacy_path_only_config_uses_safe_defaults() {
        let config: WebSocketAcceptorConfig = toml::from_str("path = '/trojan'").unwrap();
        assert_eq!(config.handshake_timeout_secs, 10);
        assert_eq!(config.max_handshake_size, 8 * 1024);
        assert_eq!(config.options.max_message_size, 1024 * 1024);
    }

    #[tokio::test]
    async fn pre_read_handshake_preserves_websocket_data() {
        let (server_io, client_io) = tokio::io::duplex(16 * 1024);
        let server = async move {
            let mut server_io = server_io;
            let head = read_request_head(&mut server_io, 8 * 1024).await.unwrap();
            assert!(is_trojan_go_websocket_request(&head, "/trojan"));
            let prefixed = PrefixedStream::new(head, server_io);
            let websocket = accept_hdr_async_with_config(
                prefixed,
                WebSocketCallback {
                    path: Arc::from("/trojan"),
                },
                Some(WebSocketConfig::default()),
            )
            .await
            .unwrap();
            let mut stream = BinaryWsStream::new(websocket);
            let mut payload = [0u8; 7];
            stream.read_exact(&mut payload).await.unwrap();
            payload
        };
        let client = async move {
            let (mut websocket, _) = client_async("ws://example.com/trojan", client_io)
                .await
                .unwrap();
            websocket
                .send(Message::Binary(bytes::Bytes::from_static(b"payload")))
                .await
                .unwrap();
        };

        let (payload, ()) = tokio::join!(server, client);
        assert_eq!(&payload, b"payload");
    }
}
