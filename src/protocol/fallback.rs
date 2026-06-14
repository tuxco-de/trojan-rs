use crate::protocol::new_error;
use serde::Deserialize;
use std::{fs, io, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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
pub struct FallbackConfig {
    page: String,
    #[serde(default = "default_request_timeout_secs")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_max_request_size")]
    pub max_request_size: usize,
}

/// A shared, lightweight static-page server used by both `WebSocketAcceptor`
/// and `TrojanAcceptor` to respond to non-proxy HTTP requests.
#[derive(Clone)]
pub struct FallbackPage {
    body: Arc<[u8]>,
    request_timeout: Duration,
    max_request_size: usize,
}

impl FallbackPage {
    /// Creates a `FallbackPage` from the given configuration.  Returns `None`
    /// when no fallback config is provided.
    pub fn new(config: Option<&FallbackConfig>) -> io::Result<Option<Self>> {
        let Some(config) = config else {
            return Ok(None);
        };
        if config.request_timeout_secs == 0 || config.max_request_size < 256 {
            return Err(new_error("invalid fallback request limits"));
        }
        let body = fs::read(&config.page)?;
        if body.len() > MAX_PAGE_SIZE {
            return Err(new_error(format!(
                "fallback page exceeds {} bytes",
                MAX_PAGE_SIZE
            )));
        }
        Ok(Some(Self {
            body: body.into(),
            request_timeout: Duration::from_secs(config.request_timeout_secs),
            max_request_size: config.max_request_size,
        }))
    }

    /// Serve a static page to `stream`.  `prefix` contains bytes that have
    /// already been read from the stream (e.g. the first 4 bytes used for
    /// protocol detection, or the full HTTP request head).
    ///
    /// This method spawns a background task so it never blocks the caller's
    /// accept loop.
    pub fn serve<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
        &self,
        mut stream: T,
        prefix: Vec<u8>,
    ) {
        let body = self.body.clone();
        let request_timeout = self.request_timeout;
        let max_request_size = self.max_request_size;
        tokio::spawn(async move {
            let result = timeout(request_timeout, async {
                // If the prefix already contains a complete HTTP request head
                // we don't need to read more from the stream.
                let request = if find_header_end(&prefix).is_some() || !looks_like_http(&prefix) {
                    prefix
                } else {
                    // We need to keep reading the rest of the HTTP head.
                    let mut request = prefix;
                    while find_header_end(&request).is_none() {
                        if request.len() >= max_request_size {
                            break;
                        }
                        let remaining = (max_request_size - request.len()).min(1024);
                        let mut buffer = [0u8; 1024];
                        let read = stream.read(&mut buffer[..remaining]).await?;
                        if read == 0 {
                            break;
                        }
                        request.extend_from_slice(&buffer[..read]);
                    }
                    request
                };

                let parsed = parse_request(&request);
                let status = if parsed.valid {
                    "200 OK"
                } else {
                    "400 Bad Request"
                };
                write_page(&mut stream, status, parsed.is_head, &body).await
            })
            .await;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => log::debug!("fallback response failed: {}", error),
                Err(_) => log::debug!("fallback response timed out"),
            }
        });
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

struct ParsedRequest {
    valid: bool,
    is_head: bool,
}

fn parse_request(request: &[u8]) -> ParsedRequest {
    let Some(header_end) = find_header_end(request) else {
        return ParsedRequest {
            valid: false,
            is_head: false,
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
        };
    }
    let method = parsed.method.unwrap_or_default();
    ParsedRequest {
        valid: true,
        is_head: method == "HEAD",
    }
}

pub fn looks_like_http(request: &[u8]) -> bool {
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

pub fn find_header_end(buf: &[u8]) -> Option<usize> {
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
    use super::*;

    #[test]
    fn detects_http_methods() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\n"));
        assert!(looks_like_http(b"POST /data HTTP/1.1\r\n"));
        assert!(looks_like_http(b"HEAD / HTTP/1.1\r\n"));
        assert!(!looks_like_http(b"\x01\x00\x00\x00"));
        assert!(!looks_like_http(b"abc"));
    }

    #[test]
    fn finds_header_end() {
        assert_eq!(
            find_header_end(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some(27)
        );
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn parses_valid_get() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let parsed = parse_request(req);
        assert!(parsed.valid);
        assert!(!parsed.is_head);
    }

    #[test]
    fn parses_head_request() {
        let req = b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let parsed = parse_request(req);
        assert!(parsed.valid);
        assert!(parsed.is_head);
    }

    #[tokio::test]
    async fn write_page_includes_content_length() {
        let mut buf = Vec::new();
        write_page(&mut buf, "200 OK", false, b"<h1>test</h1>")
            .await
            .unwrap();
        let response = String::from_utf8(buf).unwrap();
        assert!(response.contains("Content-Length: 13\r\n"));
        assert!(response.ends_with("<h1>test</h1>"));
    }

    #[tokio::test]
    async fn head_response_omits_body() {
        let mut buf = Vec::new();
        write_page(&mut buf, "200 OK", true, b"<h1>test</h1>")
            .await
            .unwrap();
        let response = String::from_utf8(buf).unwrap();
        assert!(response.contains("Content-Length: 13\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
    }
}
