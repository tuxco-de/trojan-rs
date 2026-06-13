use crate::protocol::{new_error, AcceptResult, DummyUdpStream, ProxyAcceptor, ProxyTcpStream};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use serde::Deserialize;
use std::{
    fs, io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::timeout;

const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MAX_REQUEST_SIZE: usize = 8 * 1024;
const MAX_PAGE_SIZE: usize = 2 * 1024 * 1024;

fn default_request_timeout_secs() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECS
}

fn default_max_request_size() -> usize {
    DEFAULT_MAX_REQUEST_SIZE
}

#[derive(Deserialize)]
pub struct CamouflageConfig {
    page: String,
    #[serde(default = "default_request_timeout_secs")]
    request_timeout_secs: u64,
    #[serde(default = "default_max_request_size")]
    max_request_size: usize,
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

impl<T: ProxyTcpStream> ProxyTcpStream for PrefixedStream<T> {}

struct StaticPage {
    body: Arc<[u8]>,
}

pub struct CamouflageAcceptor<T: ProxyAcceptor> {
    inner: T,
    page: Option<StaticPage>,
    websocket_path: Option<String>,
    request_timeout: Duration,
    max_request_size: usize,
}

#[async_trait]
impl<T: ProxyAcceptor> ProxyAcceptor for CamouflageAcceptor<T> {
    type TS = PrefixedStream<T::TS>;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        loop {
            let (mut stream, addr) = self.inner.accept().await?.unwrap_tcp_with_addr();
            let page = match &self.page {
                Some(page) => page,
                None => {
                    return Ok(AcceptResult::Tcp((
                        PrefixedStream::new(Vec::new(), stream),
                        addr,
                    )))
                }
            };

            let request = match timeout(
                self.request_timeout,
                read_request_head(&mut stream, self.max_request_size),
            )
            .await
            {
                Ok(Ok(request)) => request,
                Ok(Err(error)) => {
                    log::debug!("camouflage request read failed: {}", error);
                    continue;
                }
                Err(_) => {
                    log::debug!("camouflage request timed out");
                    continue;
                }
            };

            if !looks_like_http(&request) {
                return Ok(AcceptResult::Tcp((
                    PrefixedStream::new(request, stream),
                    addr,
                )));
            }

            let parsed = parse_request(&request, self.websocket_path.as_deref());
            if parsed.is_tunnel {
                return Ok(AcceptResult::Tcp((
                    PrefixedStream::new(request, stream),
                    addr,
                )));
            }

            let status = if parsed.valid {
                "200 OK"
            } else {
                "400 Bad Request"
            };
            let body = page.body.clone();
            let response_timeout = self.request_timeout;
            tokio::spawn(async move {
                match timeout(
                    response_timeout,
                    write_page(&mut stream, status, parsed.is_head, &body),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => log::debug!("camouflage response failed: {}", error),
                    Err(_) => log::debug!("camouflage response timed out"),
                }
            });
        }
    }
}

impl<T: ProxyAcceptor> CamouflageAcceptor<T> {
    pub fn new(
        config: Option<&CamouflageConfig>,
        websocket_path: Option<&str>,
        inner: T,
    ) -> io::Result<Self> {
        let Some(config) = config else {
            return Ok(Self {
                inner,
                page: None,
                websocket_path: websocket_path.map(str::to_owned),
                request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_SECS),
                max_request_size: DEFAULT_MAX_REQUEST_SIZE,
            });
        };
        if config.request_timeout_secs == 0 || config.max_request_size < 256 {
            return Err(new_error("invalid camouflage request limits"));
        }
        let body = fs::read(&config.page)?;
        if body.len() > MAX_PAGE_SIZE {
            return Err(new_error(format!(
                "camouflage page exceeds {} bytes",
                MAX_PAGE_SIZE
            )));
        }
        Ok(Self {
            inner,
            page: Some(StaticPage { body: body.into() }),
            websocket_path: websocket_path.map(str::to_owned),
            request_timeout: Duration::from_secs(config.request_timeout_secs),
            max_request_size: config.max_request_size,
        })
    }
}

struct ParsedRequest {
    valid: bool,
    is_head: bool,
    is_tunnel: bool,
}

fn parse_request(request: &[u8], websocket_path: Option<&str>) -> ParsedRequest {
    let Some(header_end) = find_header_end(request) else {
        return ParsedRequest {
            valid: false,
            is_head: false,
            is_tunnel: false,
        };
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    if !matches!(
        parsed.parse(&request[..header_end]),
        Ok(httparse::Status::Complete(_))
    ) {
        return ParsedRequest {
            valid: false,
            is_head: false,
            is_tunnel: false,
        };
    }

    let method = parsed.method.unwrap_or_default();
    let path_matches = websocket_path
        .zip(parsed.path)
        .map(|(expected, path)| path.split('?').next() == Some(expected))
        .unwrap_or(false);
    let has_upgrade = parsed.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("upgrade")
            && std::str::from_utf8(header.value)
                .map(|value| value.trim().eq_ignore_ascii_case("websocket"))
                .unwrap_or(false)
    });
    let has_connection_upgrade = parsed.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("connection")
            && std::str::from_utf8(header.value)
                .map(|value| {
                    value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
                })
                .unwrap_or(false)
    });
    let has_websocket_key = parsed.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("sec-websocket-key") && !header.value.is_empty()
    });
    let has_websocket_version = parsed.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("sec-websocket-version")
            && std::str::from_utf8(header.value)
                .map(|value| value.trim() == "13")
                .unwrap_or(false)
    });
    ParsedRequest {
        valid: true,
        is_head: method == "HEAD",
        is_tunnel: method == "GET"
            && path_matches
            && has_upgrade
            && has_connection_upgrade
            && has_websocket_key
            && has_websocket_version,
    }
}

async fn read_request_head<T: AsyncRead + Unpin>(
    stream: &mut T,
    max_size: usize,
) -> io::Result<Vec<u8>> {
    let mut request = Vec::with_capacity(1024);
    let mut first = [0u8; 4];
    stream.read_exact(&mut first).await?;
    request.extend_from_slice(&first);
    if !looks_like_http(&request) {
        return Ok(request);
    }

    while find_header_end(&request).is_none() {
        if request.len() >= max_size {
            return Err(new_error("camouflage request headers are too large"));
        }
        let remaining = (max_size - request.len()).min(1024);
        let mut buffer = [0u8; 1024];
        let read = stream.read(&mut buffer[..remaining]).await?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
    }
    Ok(request)
}

fn looks_like_http(request: &[u8]) -> bool {
    matches!(
        request.get(..4),
        Some(
            [b'G', b'E', b'T', b' ']
                | [b'H', b'E', b'A', b'D']
                | [b'P', b'O', b'S', b'T']
                | [b'P', b'U', b'T', b' ']
                | [b'D', b'E', b'L', b'E']
                | [b'O', b'P', b'T', b'I']
                | [b'P', b'A', b'T', b'C']
                | [b'T', b'R', b'A', b'C']
                | [b'C', b'O', b'N', b'N']
        )
    )
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

async fn write_page<T: AsyncWrite + Unpin>(
    stream: &mut T,
    status: &str,
    head_only: bool,
    body: &[u8],
) -> io::Result<()> {
    let response_head = format!(
        "HTTP/1.1 {status}\r\nServer: nginx\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        body.len()
    );
    stream.write_all(response_head.as_bytes()).await?;
    if !head_only {
        stream.write_all(body).await?;
    }
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::{parse_request, CamouflageAcceptor, StaticPage, DEFAULT_MAX_REQUEST_SIZE};
    use crate::protocol::{AcceptResult, Address, DummyUdpStream, ProxyAcceptor, ProxyTcpStream};
    use async_trait::async_trait;
    use std::{
        collections::VecDeque,
        io,
        pin::Pin,
        sync::Arc,
        task::{Context, Poll},
        time::Duration,
    };
    use tokio::{
        io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
        sync::Mutex,
    };

    struct TestStream(DuplexStream);

    impl AsyncRead for TestStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for TestStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl ProxyTcpStream for TestStream {}

    struct QueueAcceptor {
        streams: Mutex<VecDeque<TestStream>>,
    }

    #[async_trait]
    impl ProxyAcceptor for QueueAcceptor {
        type TS = TestStream;
        type US = DummyUdpStream;

        async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
            let stream =
                self.streams.lock().await.pop_front().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::UnexpectedEof, "no test stream")
                })?;
            Ok(AcceptResult::Tcp((
                stream,
                Address::SocketAddress("127.0.0.1:443".parse().unwrap()),
            )))
        }
    }

    fn acceptor(
        servers: Vec<TestStream>,
        websocket_path: Option<&str>,
    ) -> CamouflageAcceptor<QueueAcceptor> {
        CamouflageAcceptor {
            inner: QueueAcceptor {
                streams: Mutex::new(servers.into()),
            },
            page: Some(StaticPage {
                body: Arc::from(&b"<h1>cover</h1>"[..]),
            }),
            websocket_path: websocket_path.map(str::to_owned),
            request_timeout: Duration::from_secs(1),
            max_request_size: DEFAULT_MAX_REQUEST_SIZE,
        }
    }

    #[test]
    fn recognizes_only_the_configured_websocket_tunnel() {
        let tunnel = b"GET /tunnel?ed=2048 HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-WebSocket-Key: Zm9vYmFyYmF6cXV4\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let static_request =
            b"GET /other HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\n\r\n";
        let incomplete_upgrade = b"GET /tunnel HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";

        assert!(parse_request(tunnel, Some("/tunnel")).is_tunnel);
        assert!(!parse_request(static_request, Some("/tunnel")).is_tunnel);
        assert!(!parse_request(incomplete_upgrade, Some("/tunnel")).is_tunnel);
    }

    #[tokio::test]
    async fn serves_http_then_preserves_the_next_binary_stream() {
        let (server_http, mut client_http) = duplex(4096);
        let (server_binary, mut client_binary) = duplex(4096);
        let acceptor = acceptor(
            vec![TestStream(server_http), TestStream(server_binary)],
            Some("/tunnel"),
        );
        let task = tokio::spawn(async move { acceptor.accept().await });

        client_http
            .write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        client_http.read_to_end(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.ends_with(b"<h1>cover</h1>"));

        let payload = b"abcd-native-tunnel";
        client_binary.write_all(payload).await.unwrap();
        let result = task.await.unwrap().unwrap();
        let (mut stream, _) = result.unwrap_tcp_with_addr();
        let mut received = vec![0u8; payload.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, payload);
    }

    #[tokio::test]
    async fn passes_websocket_handshake_to_the_next_acceptor() {
        let request = b"GET /tunnel HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: Zm9vYmFyYmF6cXV4\r\nSec-WebSocket-Version: 13\r\n\r\n";
        let (server, mut client) = duplex(4096);
        let acceptor = acceptor(vec![TestStream(server)], Some("/tunnel"));
        client.write_all(request).await.unwrap();

        let result = acceptor.accept().await.unwrap();
        let (mut stream, _) = result.unwrap_tcp_with_addr();
        let mut received = vec![0u8; request.len()];
        stream.read_exact(&mut received).await.unwrap();
        assert_eq!(received, request);
    }

    #[tokio::test]
    async fn head_response_has_content_length_without_a_body() {
        let (server, mut client) = duplex(4096);
        let acceptor = acceptor(vec![TestStream(server)], None);
        let task = tokio::spawn(async move { acceptor.accept().await });
        client
            .write_all(b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        let response = String::from_utf8(response).unwrap();
        assert!(response.contains("Content-Length: 14\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
        assert!(task.await.unwrap().is_err());
    }
}
