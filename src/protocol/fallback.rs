use crate::protocol::new_error;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use bytes::Bytes;
use http::{Method, Response, StatusCode};
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
    pub dashboard_password: Option<String>,
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
    dashboard_password: Option<Arc<str>>,
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
        if config
            .dashboard_password
            .as_ref()
            .is_some_and(|password| password.is_empty())
        {
            return Err(new_error("dashboard password must not be empty"));
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
            dashboard_password: config.dashboard_password.as_deref().map(Arc::from),
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
        let dashboard_password = self.dashboard_password.clone();
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

                let route = route_request(&request, dashboard_password.as_deref());
                let json_buffer;

                let response = match route {
                    FallbackRoute::Page { head_only } => ResponseSpec {
                        status: "200 OK",
                        content_type: "text/html; charset=utf-8",
                        extra_headers: "Cache-Control: no-cache\r\n",
                        head_only,
                        body: &body,
                    },
                    FallbackRoute::Dashboard { head_only } => ResponseSpec {
                        status: "200 OK",
                        content_type: "text/html; charset=utf-8",
                        extra_headers: "Cache-Control: no-cache\r\n",
                        head_only,
                        body: include_bytes!("../../assets/dashboard.html"),
                    },
                    FallbackRoute::ApiStatus { head_only } => {
                        let global = crate::proxy::metrics::global_metrics();
                        let clients_map = global.clients.read().await;

                        #[derive(serde::Serialize)]
                        struct ClientInfo {
                            id: u64,
                            addr: String,
                            uptime_secs: u64,
                            upload_bytes: u64,
                            download_bytes: u64,
                        }

                        #[derive(serde::Serialize)]
                        struct MetricsResponse {
                            total_upload: u64,
                            total_download: u64,
                            clients: Vec<ClientInfo>,
                        }

                        let mut clients = Vec::new();
                        for client in clients_map.values() {
                            clients.push(ClientInfo {
                                id: client.id,
                                addr: client.addr.clone(),
                                uptime_secs: client.start_time.elapsed().as_secs(),
                                upload_bytes: client
                                    .upload_bytes
                                    .load(std::sync::atomic::Ordering::Relaxed),
                                download_bytes: client
                                    .download_bytes
                                    .load(std::sync::atomic::Ordering::Relaxed),
                            });
                        }
                        clients.sort_by_key(|c| std::cmp::Reverse(c.id));

                        let resp = MetricsResponse {
                            total_upload: global
                                .total_upload
                                .load(std::sync::atomic::Ordering::Relaxed),
                            total_download: global
                                .total_download
                                .load(std::sync::atomic::Ordering::Relaxed),
                            clients,
                        };

                        json_buffer = serde_json::to_string(&resp).unwrap_or_default();

                        ResponseSpec {
                            status: "200 OK",
                            content_type: "application/json; charset=utf-8",
                            extra_headers: "Cache-Control: no-store\r\n",
                            head_only,
                            body: json_buffer.as_bytes(),
                        }
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
                    FallbackRoute::Unauthorized { head_only } => ResponseSpec {
                        status: "401 Unauthorized",
                        content_type: "text/html; charset=utf-8",
                        extra_headers: "WWW-Authenticate: Basic realm=\"trojan-rs dashboard\"\r\nCache-Control: no-store\r\n",
                        head_only,
                        body: b"<!doctype html><title>401 Unauthorized</title><h1>Unauthorized</h1>",
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

    pub fn serve_h2<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(&self, stream: T) {
        let page = self.clone();
        tokio::spawn(async move {
            let mut connection =
                match timeout(page.request_timeout, h2::server::handshake(stream)).await {
                    Ok(Ok(connection)) => connection,
                    Ok(Err(error)) => {
                        log::debug!("HTTP/2 fallback handshake failed: {}", error);
                        return;
                    }
                    Err(_) => {
                        log::debug!("HTTP/2 fallback handshake timed out");
                        return;
                    }
                };
            while let Some(request) = connection.accept().await {
                let (request, respond) = match request {
                    Ok(request) => request,
                    Err(error) => {
                        log::debug!("HTTP/2 fallback request failed: {}", error);
                        break;
                    }
                };
                let route = route_h2_request(&request, page.dashboard_password.as_deref());
                if let Err(error) = page.write_h2_response(route, respond).await {
                    log::debug!("HTTP/2 fallback response failed: {}", error);
                    break;
                }
            }
        });
    }

    async fn write_h2_response(
        &self,
        route: FallbackRoute,
        mut respond: h2::server::SendResponse<Bytes>,
    ) -> io::Result<()> {
        let (status, content_type, cache_control, www_authenticate, head_only, body) = match route {
            FallbackRoute::Page { head_only } => (
                StatusCode::OK,
                "text/html; charset=utf-8",
                "no-cache",
                None,
                head_only,
                self.body.to_vec(),
            ),
            FallbackRoute::Dashboard { head_only } => (
                StatusCode::OK,
                "text/html; charset=utf-8",
                "no-cache",
                None,
                head_only,
                include_bytes!("../../assets/dashboard.html").to_vec(),
            ),
            FallbackRoute::ApiStatus { head_only } => (
                StatusCode::OK,
                "application/json; charset=utf-8",
                "no-store",
                None,
                head_only,
                metrics_json().await.into_bytes(),
            ),
            FallbackRoute::Robots { head_only } => (
                StatusCode::OK,
                "text/plain; charset=utf-8",
                "public, max-age=3600",
                None,
                head_only,
                ROBOTS_BODY.to_vec(),
            ),
            FallbackRoute::NotFound { head_only } => (
                StatusCode::NOT_FOUND,
                "text/html; charset=utf-8",
                "no-cache",
                None,
                head_only,
                NOT_FOUND_BODY.to_vec(),
            ),
            FallbackRoute::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                "text/html; charset=utf-8",
                "no-cache",
                None,
                false,
                METHOD_NOT_ALLOWED_BODY.to_vec(),
            ),
            FallbackRoute::BadRequest => (
                StatusCode::BAD_REQUEST,
                "text/html; charset=utf-8",
                "no-cache",
                None,
                false,
                BAD_REQUEST_BODY.to_vec(),
            ),
            FallbackRoute::Unauthorized { head_only } => (
                StatusCode::UNAUTHORIZED,
                "text/html; charset=utf-8",
                "no-store",
                Some("Basic realm=\"trojan-rs dashboard\""),
                head_only,
                b"<!doctype html><title>401 Unauthorized</title><h1>Unauthorized</h1>".to_vec(),
            ),
        };
        let mut response = Response::builder()
            .status(status)
            .header("content-type", content_type)
            .header("content-length", body.len())
            .header("cache-control", cache_control)
            .header("server", "nginx")
            .header("x-content-type-options", "nosniff");
        if status == StatusCode::METHOD_NOT_ALLOWED {
            response = response.header("allow", "GET, HEAD");
        }
        if let Some(value) = www_authenticate {
            response = response.header("www-authenticate", value);
        }
        let mut send = respond
            .send_response(response.body(()).unwrap(), head_only)
            .map_err(h2_error)?;
        if !head_only {
            send.send_data(Bytes::from(body), true).map_err(h2_error)?;
        }
        Ok(())
    }
}

async fn metrics_json() -> String {
    let global = crate::proxy::metrics::global_metrics();
    let clients_map = global.clients.read().await;

    #[derive(serde::Serialize)]
    struct ClientInfo {
        id: u64,
        addr: String,
        uptime_secs: u64,
        upload_bytes: u64,
        download_bytes: u64,
    }

    #[derive(serde::Serialize)]
    struct MetricsResponse {
        total_upload: u64,
        total_download: u64,
        clients: Vec<ClientInfo>,
    }

    let mut clients = Vec::new();
    for client in clients_map.values() {
        clients.push(ClientInfo {
            id: client.id,
            addr: client.addr.clone(),
            uptime_secs: client.start_time.elapsed().as_secs(),
            upload_bytes: client
                .upload_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
            download_bytes: client
                .download_bytes
                .load(std::sync::atomic::Ordering::Relaxed),
        });
    }
    clients.sort_by_key(|client| std::cmp::Reverse(client.id));
    serde_json::to_string(&MetricsResponse {
        total_upload: global
            .total_upload
            .load(std::sync::atomic::Ordering::Relaxed),
        total_download: global
            .total_download
            .load(std::sync::atomic::Ordering::Relaxed),
        clients,
    })
    .unwrap_or_default()
}

fn h2_error(error: h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error)
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

#[derive(Debug, Eq, PartialEq)]
enum FallbackRoute {
    Page { head_only: bool },
    Dashboard { head_only: bool },
    ApiStatus { head_only: bool },
    Robots { head_only: bool },
    NotFound { head_only: bool },
    MethodNotAllowed,
    BadRequest,
    Unauthorized { head_only: bool },
}

fn route_request(request: &[u8], dashboard_password: Option<&str>) -> FallbackRoute {
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
        "/dashboard" => {
            if is_dashboard_authorized(parsed.headers, dashboard_password) {
                FallbackRoute::Dashboard { head_only }
            } else if dashboard_password.is_some() {
                FallbackRoute::Unauthorized { head_only }
            } else {
                FallbackRoute::NotFound { head_only }
            }
        }
        "/api/status" => {
            if is_dashboard_authorized(parsed.headers, dashboard_password) {
                FallbackRoute::ApiStatus { head_only }
            } else if dashboard_password.is_some() {
                FallbackRoute::Unauthorized { head_only }
            } else {
                FallbackRoute::NotFound { head_only }
            }
        }
        "/robots.txt" => FallbackRoute::Robots { head_only },
        _ => FallbackRoute::NotFound { head_only },
    }
}

fn route_h2_request(
    request: &http::Request<h2::RecvStream>,
    dashboard_password: Option<&str>,
) -> FallbackRoute {
    let authorization = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    route_h2_parts(
        request.method(),
        request.uri().path(),
        authorization,
        dashboard_password,
    )
}

fn route_h2_parts(
    method: &Method,
    path: &str,
    authorization: Option<&str>,
    dashboard_password: Option<&str>,
) -> FallbackRoute {
    let head_only = method == Method::HEAD;
    if method != Method::GET && !head_only {
        return FallbackRoute::MethodNotAllowed;
    }
    let authorized =
        authorization.is_some_and(|value| is_dashboard_authorized_value(value, dashboard_password));
    match path {
        "/" | "/index.html" => FallbackRoute::Page { head_only },
        "/dashboard" => {
            if authorized {
                FallbackRoute::Dashboard { head_only }
            } else if dashboard_password.is_some() {
                FallbackRoute::Unauthorized { head_only }
            } else {
                FallbackRoute::NotFound { head_only }
            }
        }
        "/api/status" => {
            if authorized {
                FallbackRoute::ApiStatus { head_only }
            } else if dashboard_password.is_some() {
                FallbackRoute::Unauthorized { head_only }
            } else {
                FallbackRoute::NotFound { head_only }
            }
        }
        "/robots.txt" => FallbackRoute::Robots { head_only },
        _ => FallbackRoute::NotFound { head_only },
    }
}

fn is_dashboard_authorized(
    headers: &[httparse::Header<'_>],
    dashboard_password: Option<&str>,
) -> bool {
    let Some(header) = headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("authorization"))
    else {
        return false;
    };
    let Ok(value) = std::str::from_utf8(header.value) else {
        return false;
    };
    is_dashboard_authorized_value(value, dashboard_password)
}

fn is_dashboard_authorized_value(value: &str, dashboard_password: Option<&str>) -> bool {
    let Some(password) = dashboard_password else {
        return false;
    };
    let Some((scheme, token)) = value.split_once(' ') else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("basic") {
        return false;
    };
    let expected = BASE64_STANDARD.encode(format!("admin:{password}"));
    constant_time_eq(token.trim().as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = a.len() ^ b.len();
    for i in 0..a.len().max(b.len()) {
        let left = a.get(i).copied().unwrap_or(0);
        let right = b.get(i).copied().unwrap_or(0);
        diff |= (left ^ right) as usize;
    }
    diff == 0
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
        assert_eq!(
            route_request(req, None),
            FallbackRoute::Page { head_only: false }
        );
    }

    #[test]
    fn parses_head_request() {
        let req = b"HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            route_request(req, None),
            FallbackRoute::Page { head_only: true }
        );
    }

    #[test]
    fn routes_http2_requests_like_http1() {
        assert_eq!(
            route_h2_parts(&Method::GET, "/", None, None),
            FallbackRoute::Page { head_only: false }
        );
        assert_eq!(
            route_h2_parts(&Method::HEAD, "/robots.txt", None, None),
            FallbackRoute::Robots { head_only: true }
        );
        assert_eq!(
            route_h2_parts(&Method::POST, "/", None, None),
            FallbackRoute::MethodNotAllowed
        );
        let token = BASE64_STANDARD.encode("admin:secret");
        assert_eq!(
            route_h2_parts(
                &Method::GET,
                "/api/status",
                Some(&format!("Basic {token}")),
                Some("secret"),
            ),
            FallbackRoute::ApiStatus { head_only: false }
        );
    }

    #[tokio::test]
    async fn serves_the_fallback_page_over_http2() {
        let page = FallbackPage {
            body: Arc::from(&b"fallback page"[..]),
            dashboard_password: None,
            request_timeout: Duration::from_secs(1),
            max_request_size: DEFAULT_MAX_REQUEST_SIZE,
        };
        let (server, client) = tokio::io::duplex(16 * 1024);
        page.serve_h2(server);

        let (mut sender, connection) = h2::client::handshake(client).await.unwrap();
        let connection = tokio::spawn(connection);
        let request = http::Request::builder()
            .method(Method::GET)
            .uri("https://example.com/")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let data = std::future::poll_fn(|cx| body.poll_data(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..], b"fallback page");
        connection.abort();
    }

    #[test]
    fn routes_static_and_error_responses() {
        assert_eq!(
            route_request(
                b"GET /robots.txt HTTP/1.1\r\nHost: example.com\r\n\r\n",
                None
            ),
            FallbackRoute::Robots { head_only: false }
        );
        assert_eq!(
            route_request(b"GET /missing HTTP/1.1\r\nHost: example.com\r\n\r\n", None),
            FallbackRoute::NotFound { head_only: false }
        );
        assert_eq!(
            route_request(b"POST / HTTP/1.1\r\nHost: example.com\r\n\r\n", None),
            FallbackRoute::MethodNotAllowed
        );
        assert_eq!(
            route_request(b"GET / HTTP/1.1\r\n\r\n", None),
            FallbackRoute::BadRequest
        );
    }

    #[test]
    fn protects_dashboard_routes() {
        let request = b"GET /dashboard HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(
            route_request(request, None),
            FallbackRoute::NotFound { head_only: false }
        );
        assert_eq!(
            route_request(request, Some("secret")),
            FallbackRoute::Unauthorized { head_only: false }
        );

        let token = BASE64_STANDARD.encode("admin:secret");
        let request = format!(
            "GET /api/status HTTP/1.1\r\nHost: example.com\r\nAuthorization: Basic {token}\r\n\r\n"
        );
        assert_eq!(
            route_request(request.as_bytes(), Some("secret")),
            FallbackRoute::ApiStatus { head_only: false }
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
