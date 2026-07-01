use super::{
    default_handshake_timeout_secs, default_max_early_data, default_max_handshake_size, new_error,
    BinaryWsStream, WebSocketOptions,
};
use crate::protocol::fallback::{FallbackConfig, FallbackPage};
use crate::protocol::{AcceptResult, DummyUdpStream, ProxyAcceptor, ProxyTcpStream};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use bytes::{Buf, Bytes};
use serde::Deserialize;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
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
    #[serde(default)]
    max_early_data: usize,
    early_data_header_name: Option<String>,
    #[serde(flatten)]
    options: WebSocketOptions,
}

struct WebSocketCallback {
    path: Arc<str>,
    allow_path_early_data: bool,
    response_protocol: Option<Arc<str>>,
}

impl Callback for WebSocketCallback {
    fn on_request(self, request: &Request, response: Response) -> Result<Response, ErrorResponse> {
        let date_str = httpdate::fmt_http_date(std::time::SystemTime::now());

        if !websocket_path_matches(
            request.uri().path(),
            request.uri().query(),
            self.path.as_ref(),
            self.allow_path_early_data,
        ) {
            let mut resp = ErrorResponse::new(None);
            *resp.status_mut() = StatusCode::NOT_FOUND;
            if let Ok(val) = date_str.parse() {
                resp.headers_mut().insert("Date", val);
            }
            if let Ok(val) = "close".parse() {
                resp.headers_mut().insert("Connection", val);
            }

            log::debug!(
                "invalid websocket path: {}, expected: {}",
                request.uri(),
                self.path
            );
            Err(resp)
        } else {
            let mut response = response;
            if let Ok(val) = date_str.parse() {
                response.headers_mut().insert("Date", val);
            }
            if let Some(protocol) = self.response_protocol {
                if let Ok(val) = protocol.as_ref().parse() {
                    response.headers_mut().insert("Sec-WebSocket-Protocol", val);
                }
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
    max_early_data: usize,
    early_data_header_name: Option<Arc<str>>,
    websocket_config: WebSocketConfig,
    websocket_options: WebSocketOptions,
    allow_raw: bool,
    fallback: Option<FallbackPage>,
    accept_tx:
        mpsc::Sender<io::Result<AcceptResult<TrojanGoWebSocketStream<T::TS>, DummyUdpStream>>>,
    accept_rx: Arc<
        Mutex<
            mpsc::Receiver<
                io::Result<AcceptResult<TrojanGoWebSocketStream<T::TS>, DummyUdpStream>>,
            >,
        >,
    >,
    inner: T,
}

#[async_trait]
impl<T: ProxyAcceptor + 'static> ProxyAcceptor for WebSocketAcceptor<T> {
    type TS = TrojanGoWebSocketStream<T::TS>;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        loop {
            tokio::select! {
                result = async { self.accept_rx.lock().await.recv().await } => {
                    return result.ok_or_else(|| {
                        io::Error::new(io::ErrorKind::ConnectionAborted, "websocket acceptor closed")
                    })?;
                }
                result = self.inner.accept() => {
                    let (stream, addr) = result?.unwrap_tcp_with_addr();
                    let path = Arc::clone(&self.path);
                    let handshake_timeout = self.handshake_timeout;
                    let max_handshake_size = self.max_handshake_size;
                    let max_early_data = self.max_early_data;
                    let early_data_header_name = self.early_data_header_name.clone();
                    let websocket_config = self.websocket_config.clone();
                    let websocket_options = self.websocket_options;
                    let allow_raw = self.allow_raw;
                    let fallback = self.fallback.clone();
                    let accept_tx = self.accept_tx.clone();
                    tokio::spawn(async move {
                        match accept_websocket_stream(
                            stream,
                            addr,
                            path,
                            handshake_timeout,
                            max_handshake_size,
                            max_early_data,
                            early_data_header_name,
                            websocket_config,
                            websocket_options,
                            allow_raw,
                            fallback,
                        )
                        .await
                        {
                            Ok(Some(result)) => {
                                let _ = accept_tx.send(Ok(result)).await;
                            }
                            Ok(None) => {}
                            Err(error) => {
                                let _ = accept_tx.send(Err(error)).await;
                            }
                        }
                    });
                }
            }
        }
    }
}

async fn accept_websocket_stream<S>(
    mut stream: S,
    addr: crate::protocol::Address,
    path: Arc<str>,
    handshake_timeout: Duration,
    max_handshake_size: usize,
    max_early_data: usize,
    early_data_header_name: Option<Arc<str>>,
    websocket_config: WebSocketConfig,
    websocket_options: WebSocketOptions,
    allow_raw: bool,
    fallback: Option<FallbackPage>,
) -> io::Result<Option<AcceptResult<TrojanGoWebSocketStream<S>, DummyUdpStream>>>
where
    S: ProxyTcpStream + 'static,
{
    let deadline = Instant::now() + handshake_timeout;
    let request_head = timeout_at(deadline, read_request_head(&mut stream, max_handshake_size))
        .await
        .map_err(|_| new_error("websocket handshake timed out"))??;

    let is_websocket =
        is_trojan_go_websocket_request_with_options(&request_head, path.as_ref(), true);
    if !is_websocket {
        if !allow_raw {
            if let Some(ref fallback) = fallback {
                log::info!("serving fallback page to {}", addr);
                fallback.serve(stream, request_head);
                return Ok(None);
            }
            return Err(new_error("websocket upgrade required"));
        }
        let prefixed = PrefixedStream::new(request_head, stream);
        return Ok(Some(AcceptResult::Tcp((
            TrojanGoWebSocketStream::Raw(prefixed),
            addr,
        ))));
    }
    let early_data = extract_early_data(
        &request_head,
        path.as_ref(),
        max_early_data,
        early_data_header_name.as_deref(),
    )?;

    let prefixed = PrefixedStream::new(request_head, stream);
    let stream = timeout_at(
        deadline,
        accept_hdr_async_with_config(
            prefixed,
            WebSocketCallback {
                path,
                allow_path_early_data: true,
                response_protocol: early_data.response_protocol.clone(),
            },
            Some(websocket_config),
        ),
    )
    .await
    .map_err(|_| new_error("websocket handshake timed out"))?
    .map_err(new_error)?;
    Ok(Some(AcceptResult::Tcp((
        TrojanGoWebSocketStream::WebSocket(Box::new(BinaryWsStream::new_with_options(
            stream,
            early_data.payload,
            websocket_options.keepalive_interval_secs,
            websocket_options.max_write_frame_size,
        ))),
        addr,
    ))))
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
        let (accept_tx, accept_rx) = mpsc::channel(1024);
        Ok(Self {
            inner,
            path: Arc::from(config.path.as_str()),
            handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
            max_handshake_size: config.max_handshake_size,
            max_early_data: config.max_early_data,
            early_data_header_name: config
                .early_data_header_name
                .as_ref()
                .map(|header| Arc::from(header.as_str())),
            websocket_config,
            websocket_options: config.options,
            allow_raw,
            fallback,
            accept_tx,
            accept_rx: Arc::new(Mutex::new(accept_rx)),
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
    if config.max_early_data > default_max_early_data() {
        return Err(new_error("websocket early data limit is too large"));
    }
    if let Some(header_name) = config.early_data_header_name.as_ref() {
        if !header_name.is_empty() && !is_valid_header_name(header_name) {
            return Err(new_error("invalid websocket early data header name"));
        }
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

#[cfg(test)]
fn is_trojan_go_websocket_request(request: &[u8], expected_path: &str) -> bool {
    is_trojan_go_websocket_request_with_options(request, expected_path, false)
}

fn is_trojan_go_websocket_request_with_options(
    request: &[u8],
    expected_path: &str,
    allow_path_early_data: bool,
) -> bool {
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
    let path_matches = parsed.path.is_some_and(|path| {
        let (path, query) = path
            .split_once('?')
            .map_or((path, None), |(path, query)| (path, Some(query)));
        websocket_path_matches(path, query, expected_path, allow_path_early_data)
    });
    let header_has_token = |name: &str, expected: &str| {
        parsed.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case(name)
                && std::str::from_utf8(header.value)
                    .map(|value| {
                        value
                            .split(',')
                            .any(|token| token.trim().eq_ignore_ascii_case(expected))
                    })
                    .unwrap_or(false)
        })
    };
    let header_equals = |name: &str, expected: &str| {
        parsed.headers.iter().any(|header| {
            header.name.eq_ignore_ascii_case(name)
                && std::str::from_utf8(header.value)
                    .map(|value| value.trim().eq_ignore_ascii_case(expected))
                    .unwrap_or(false)
        })
    };
    let header_present = |name: &str| {
        parsed
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case(name) && !header.value.is_empty())
    };

    path_matches
        && header_present("host")
        && header_has_token("connection", "upgrade")
        && header_has_token("upgrade", "websocket")
        && header_equals("sec-websocket-version", "13")
        && header_present("sec-websocket-key")
}

struct EarlyData {
    payload: Bytes,
    response_protocol: Option<Arc<str>>,
}

fn extract_early_data(
    request: &[u8],
    expected_path: &str,
    configured_limit: usize,
    configured_header: Option<&str>,
) -> io::Result<EarlyData> {
    let Some(header_end) = find_header_end(request) else {
        return Ok(EarlyData {
            payload: Bytes::new(),
            response_protocol: None,
        });
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    if !matches!(
        parsed.parse(&request[..header_end]),
        Ok(httparse::Status::Complete(_))
    ) {
        return Ok(EarlyData {
            payload: Bytes::new(),
            response_protocol: None,
        });
    }

    let request_ed_limit = parsed.path.and_then(parse_ed_limit).unwrap_or(0);
    let limit = early_data_limit(configured_limit, request_ed_limit);
    if limit == 0 {
        return Ok(EarlyData {
            payload: Bytes::new(),
            response_protocol: None,
        });
    }

    let mut header_names = Vec::with_capacity(2);
    if let Some(header_name) = configured_header.filter(|name| !name.is_empty()) {
        header_names.push(header_name);
    }
    if !header_names
        .iter()
        .any(|name| name.eq_ignore_ascii_case("Sec-WebSocket-Protocol"))
    {
        header_names.push("Sec-WebSocket-Protocol");
    }

    for header_name in header_names {
        if let Some((encoded, response_protocol)) = header_early_data(&parsed, header_name) {
            let payload = decode_early_data(encoded)?;
            if payload.len() > limit {
                return Err(new_error("websocket early data exceeds limit"));
            }
            return Ok(EarlyData {
                payload: Bytes::from(payload),
                response_protocol,
            });
        }
    }

    if let Some(encoded) = path_early_data(parsed.path, expected_path) {
        let payload = decode_early_data(encoded)?;
        if payload.len() > limit {
            return Err(new_error("websocket early data exceeds limit"));
        }
        return Ok(EarlyData {
            payload: Bytes::from(payload),
            response_protocol: None,
        });
    }

    Ok(EarlyData {
        payload: Bytes::new(),
        response_protocol: None,
    })
}

fn early_data_limit(configured_limit: usize, request_ed_limit: usize) -> usize {
    match (configured_limit, request_ed_limit) {
        (0, 0) => 0,
        (0, request_limit) => request_limit.min(default_max_early_data()),
        (configured_limit, 0) => configured_limit,
        (configured_limit, request_limit) => configured_limit.min(request_limit),
    }
}

fn parse_ed_limit(path: &str) -> Option<usize> {
    let query = path.split_once('?')?.1;
    parse_ed_limit_from_query(query)
}

fn websocket_path_matches(
    path: &str,
    query: Option<&str>,
    expected_path: &str,
    allow_path_early_data: bool,
) -> bool {
    path == expected_path
        || (allow_path_early_data
            && query.and_then(parse_ed_limit_from_query).is_some()
            && path
                .strip_prefix(expected_path)
                .and_then(|suffix| suffix.strip_prefix('/'))
                .is_some_and(|suffix| !suffix.is_empty()))
}

fn parse_ed_limit_from_query(query: &str) -> Option<usize> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == "ed").then(|| value.parse::<usize>().ok()).flatten()
    })
}

fn header_early_data<'a>(
    parsed: &'a httparse::Request<'_, '_>,
    header_name: &str,
) -> Option<(&'a str, Option<Arc<str>>)> {
    for header in parsed.headers.iter() {
        if !header.name.eq_ignore_ascii_case(header_name) {
            continue;
        }
        let value = std::str::from_utf8(header.value).ok()?;
        let encoded = value
            .split(',')
            .map(str::trim)
            .find(|token| !token.is_empty())?;
        let response_protocol = header
            .name
            .eq_ignore_ascii_case("Sec-WebSocket-Protocol")
            .then(|| Arc::from(encoded));
        return Some((encoded, response_protocol));
    }
    None
}

fn path_early_data<'a>(path: Option<&'a str>, expected_path: &str) -> Option<&'a str> {
    let path = path?;
    let path = path.split_once('?').map_or(path, |(path, _)| path);
    let suffix = path.strip_prefix(expected_path)?;
    let encoded = suffix.strip_prefix('/')?;
    (!encoded.is_empty()).then_some(encoded)
}

fn decode_early_data(encoded: &str) -> io::Result<Vec<u8>> {
    general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| general_purpose::URL_SAFE.decode(encoded))
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(encoded))
        .or_else(|_| general_purpose::STANDARD.decode(encoded))
        .map_err(|_| new_error("invalid websocket early data encoding"))
}

fn is_valid_header_name(name: &str) -> bool {
    name.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    })
}

#[cfg(test)]
mod tests {
    use super::{
        is_trojan_go_websocket_request, read_request_head, BinaryWsStream, PrefixedStream,
        WebSocketAcceptor, WebSocketAcceptorConfig, WebSocketCallback,
    };
    use crate::protocol::{AcceptResult, Address, DummyUdpStream, ProxyAcceptor};
    use async_trait::async_trait;
    use futures_util::SinkExt;
    use std::{future::pending, io, sync::Arc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::{mpsc, Mutex};
    use tokio_tungstenite::{
        accept_hdr_async_with_config, client_async,
        tungstenite::{protocol::WebSocketConfig, Message},
    };

    struct ChannelAcceptor {
        rx: Arc<Mutex<mpsc::Receiver<tokio::io::DuplexStream>>>,
    }

    #[async_trait]
    impl ProxyAcceptor for ChannelAcceptor {
        type TS = tokio::io::DuplexStream;
        type US = DummyUdpStream;

        async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
            loop {
                if let Some(stream) = self.rx.lock().await.recv().await {
                    return Ok(AcceptResult::Tcp((stream, Address::new_dummy_address())));
                }
                pending::<()>().await;
            }
        }
    }

    #[test]
    fn recognizes_trojan_go_websocket_handshake() {
        let request = b"GET /trojan?ed=2048 HTTP/1.1\r\nHost: example.com\r\nUpgrade: WebSocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
        assert!(is_trojan_go_websocket_request(request, "/trojan"));
    }

    #[test]
    fn routes_other_http_paths_to_trojan_fallback() {
        let request = b"GET / HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
        assert!(!is_trojan_go_websocket_request(request, "/trojan"));
    }

    #[test]
    fn rejects_incomplete_websocket_handshake() {
        let request = b"GET /trojan HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
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
                    allow_path_early_data: false,
                    response_protocol: None,
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

    #[tokio::test]
    async fn slow_handshake_does_not_block_later_connections() {
        let (tx, rx) = mpsc::channel(2);
        let (slow_server, mut slow_client) = tokio::io::duplex(16 * 1024);
        let (fast_server, fast_client) = tokio::io::duplex(16 * 1024);
        tx.send(slow_server).await.unwrap();
        tx.send(fast_server).await.unwrap();

        let config: WebSocketAcceptorConfig =
            toml::from_str("path = '/trojan'\nhandshake_timeout_secs = 10\n").unwrap();
        let acceptor = WebSocketAcceptor::new_strict(
            &config,
            None,
            ChannelAcceptor {
                rx: Arc::new(Mutex::new(rx)),
            },
        )
        .unwrap();

        slow_client.write_all(b"GET ").await.unwrap();
        let fast = async move {
            let (mut websocket, _) = client_async("ws://example.com/trojan", fast_client)
                .await
                .unwrap();
            websocket
                .send(Message::Binary(bytes::Bytes::from_static(b"payload")))
                .await
                .unwrap();
        };
        let accepted = async {
            tokio::time::timeout(std::time::Duration::from_millis(500), acceptor.accept())
                .await
                .expect("later websocket connection should not wait for slow handshake")
                .unwrap()
        };

        let (accepted, ()) = tokio::join!(accepted, fast);
        let (mut stream, _) = accepted.unwrap_tcp_with_addr();
        let mut payload = [0u8; 7];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");
        drop(slow_client);
        drop(tx);
    }
}
