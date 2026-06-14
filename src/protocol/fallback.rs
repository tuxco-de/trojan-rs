use crate::protocol::new_error;
use serde::Deserialize;
use std::{fs, io, sync::Arc, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MAX_REQUEST_SIZE: usize = 8 * 1024;
const MAX_PAGE_SIZE: usize = 2 * 1024 * 1024;
const BAD_REQUEST_BODY: &[u8] =
    b"<!doctype html><title>400 Bad Request</title><h1>Bad Request</h1>";
const NOT_FOUND_BODY: &[u8] = b"<!doctype html><title>404 Not Found</title><h1>Not Found</h1>";
const METHOD_NOT_ALLOWED_BODY: &[u8] =
    b"<!doctype html><title>405 Method Not Allowed</title><h1>Method Not Allowed</h1>";
const ROBOTS_BODY: &[u8] = b"User-agent: *\r\nDisallow:\r\n";

fn default_request_timeout_secs() -> u64 {
    DEFAULT_REQUEST_TIMEOUT_SECS
}

fn default_max_request_size() -> usize {
    DEFAULT_MAX_REQUEST_SIZE
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
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
                if !looks_like_http(&prefix) {
                    return stream.shutdown().await;
                }

                // If the prefix already contains a complete HTTP request head
                // we don't need to read more from the stream.
                let request = if find_header_end(&prefix).is_some() {
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

                let route = route_request(&request);
                let response = match route {
                    FallbackRoute::Page { head_only } => ResponseSpec {
                        status: "200 OK",
                        content_type: "text/html; charset=utf-8",
                        extra_headers: "Cache-Control: no-cache\r\n",
                        head_only,
                        body: &body,
                    },
                    FallbackRoute::Robots { head_only } => ResponseSpec {
                        status: "200 OK",
                        content_type: "text/plain; charset=utf-8",
                        extra_headers: "Cache-Control: public, max-age=3600\r\n",
                        head_only,
                        body: ROBOTS_BODY,
                    },
                    FallbackRoute::NotFound { head_only } => ResponseSpec {
                        status: "404 Not Found",
                        content_type: "text/html; charset=utf-8",
                        extra_headers: "Cache-Control: no-cache\r\n",
                        head_only,
                        body: NOT_FOUND_BODY,
                    },
                    FallbackRoute::MethodNotAllowed => ResponseSpec {
                        status: "405 Method Not Allowed",
                        content_type: "text/html; charset=utf-8",
                        extra_headers: "Allow: GET, HEAD\r\nCache-Control: no-cache\r\n",
                        head_only: false,
                        body: METHOD_NOT_ALLOWED_BODY,
                    },
                    FallbackRoute::BadRequest => ResponseSpec {
                        status: "400 Bad Request",
                        content_type: "text/html; charset=utf-8",
                        extra_headers: "Cache-Control: no-cache\r\n",
                        head_only: false,
                        body: BAD_REQUEST_BODY,
                    },
                };
                write_response(&mut stream, response).await
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

#[derive(Debug, Eq, PartialEq)]
enum FallbackRoute {
    Page { head_only: bool },
    Robots { head_only: bool },
    NotFound { head_only: bool },
    MethodNotAllowed,
    BadRequest,
}

fn route_request(request: &[u8]) -> FallbackRoute {
    let Some(header_end) = find_header_end(request) else {
        return FallbackRoute::BadRequest;
    };
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Request::new(&mut headers);
    if !matches!(
        parsed.parse(&request[..header_end]),
        Ok(httparse::Status::Complete(_))
    ) {
        return FallbackRoute::BadRequest;
    }

    if !matches!(parsed.version, Some(0 | 1)) {
        return FallbackRoute::BadRequest;
    }

    if parsed.version == Some(1)
        && !parsed
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("host") && !header.value.is_empty())
    {
        return FallbackRoute::BadRequest;
    }

    let method = parsed.method.unwrap_or_default();
    let head_only = method == "HEAD";
    if method != "GET" && !head_only {
        return FallbackRoute::MethodNotAllowed;
    }

    let path = parsed
        .path
        .unwrap_or_default()
        .split_once('?')
        .map_or(parsed.path.unwrap_or_default(), |(path, _)| path);
    match path {
        "/" | "/index.html" => FallbackRoute::Page { head_only },
        "/robots.txt" => FallbackRoute::Robots { head_only },
        _ => FallbackRoute::NotFound { head_only },
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

struct ResponseSpec<'a> {
    status: &'static str,
    content_type: &'static str,
    extra_headers: &'static str,
    head_only: bool,
    body: &'a [u8],
}

async fn write_response<T: AsyncWrite + Unpin>(
    stream: &mut T,
    response: ResponseSpec<'_>,
) -> io::Result<()> {
    let date_str = httpdate::fmt_http_date(std::time::SystemTime::now());
    let response_head = format!(
        "HTTP/1.1 {}\r\nServer: nginx\r\nDate: {date_str}\r\nContent-Type: {}\r\nContent-Length: {}\r\n{}Connection: close\r\nX-Content-Type-Options: nosniff\r\n\r\n",
        response.status,
        response.content_type,
        response.body.len(),
        response.extra_headers,
    );
    stream.write_all(response_head.as_bytes()).await?;
    if !response.head_only {
        stream.write_all(response.body).await?;
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
        assert_eq!(route_request(req), FallbackRoute::Page { head_only: false });
    }

    #[test]
    fn parses_head_request() {
        let req = b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(route_request(req), FallbackRoute::Page { head_only: true });
    }

    #[test]
    fn routes_static_and_error_responses() {
        assert_eq!(
            route_request(b"GET /robots.txt HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            FallbackRoute::Robots { head_only: false }
        );
        assert_eq!(
            route_request(b"GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            FallbackRoute::NotFound { head_only: false }
        );
        assert_eq!(
            route_request(b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
            FallbackRoute::MethodNotAllowed
        );
        assert_eq!(
            route_request(b"GET / HTTP/1.1\r\n\r\n"),
            FallbackRoute::BadRequest
        );
    }

    #[tokio::test]
    async fn write_page_includes_content_length() {
        let mut buf = Vec::new();
        write_response(
            &mut buf,
            ResponseSpec {
                status: "200 OK",
                content_type: "text/html; charset=utf-8",
                extra_headers: "Cache-Control: no-cache\r\n",
                head_only: false,
                body: b"<h1>test</h1>",
            },
        )
        .await
        .unwrap();
        let response = String::from_utf8(buf).unwrap();
        assert!(response.contains("Content-Length: 13\r\n"));
        assert!(response.contains("Server: nginx\r\n"));
        assert!(response.ends_with("<h1>test</h1>"));
    }

    #[tokio::test]
    async fn head_response_omits_body() {
        let mut buf = Vec::new();
        write_response(
            &mut buf,
            ResponseSpec {
                status: "200 OK",
                content_type: "text/html; charset=utf-8",
                extra_headers: "Cache-Control: no-cache\r\n",
                head_only: true,
                body: b"<h1>test</h1>",
            },
        )
        .await
        .unwrap();
        let response = String::from_utf8(buf).unwrap();
        assert!(response.contains("Content-Length: 13\r\n"));
        assert!(response.ends_with("\r\n\r\n"));
    }
}
