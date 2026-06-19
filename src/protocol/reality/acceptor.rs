//! REALITY server-side acceptor.
//!
//! Design notes (Phase 1, VLESS + REALITY over RAW TCP):
//!
//! Unlike Xray's `MirrorConn`, which tees client bytes to the decoy `target`
//! concurrently while the TLS library reads them, this implementation *pre-reads*
//! the ClientHello off the raw socket (bounded, with a timeout) before deciding
//! what to do — the same pattern [`WebSocketAcceptor`] uses for the HTTP
//! handshake.  This keeps us off BoringSSL's internal handshake state for the
//! authentication decision and, importantly, gives us the exact ClientHello bytes
//! to use as the AES-GCM AAD.
//!
//! * On success we replay the ClientHello to BoringSSL via a [`PrefixedStream`]
//!   and complete a real TLS 1.3 handshake using a per-connection forged
//!   certificate; the resulting [`SslStream`] is handed to the VLESS acceptor.
//! * On failure (bad SNI / short id / time / auth, or anything non-TLS1.3) we
//!   dial `target`, replay the bytes we consumed, and relay transparently so the
//!   peer observes the genuine decoy site.
//!
//! Interop caveat: the forged-certificate / AAD path must match Xray clients
//! byte-for-byte and should be validated against a live `xray`/`sing-box` client.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use boring::ssl::{SslAcceptor, SslMethod, SslVersion};
use boring::x509::X509;
use bytes::{Buf, Bytes};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_boring::SslStream;

use super::cert::RealityCertificate;
use super::client_hello::{self, RECORD_TYPE_HANDSHAKE};
use super::config::RealityServer;
use super::{crypto, new_error};
use crate::protocol::{AcceptResult, Address, DummyUdpStream, ProxyAcceptor, ProxyTcpStream};

const RELAY_BUFFER_SIZE: usize = 0x4000;
const TLS_RECORD_HEADER_LEN: usize = 5;

/// A `TcpStream` with leading bytes that are yielded before live reads.
pub struct PrefixedStream {
    prefix: Bytes,
    inner: TcpStream,
}

impl PrefixedStream {
    fn new(prefix: Vec<u8>, inner: TcpStream) -> Self {
        Self {
            prefix: Bytes::from(prefix),
            inner,
        }
    }
}

impl AsyncRead for PrefixedStream {
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

impl AsyncWrite for PrefixedStream {
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

impl ProxyTcpStream for SslStream<PrefixedStream> {}

pub struct RealityAcceptor {
    tcp_listener: TcpListener,
    server: Arc<RealityServer>,
    certificate: Arc<RealityCertificate>,
}

impl RealityAcceptor {
    pub async fn new(server: RealityServer) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(&server.addr).await?;
        log::debug!("reality listen addr = {}", server.addr);
        let certificate = RealityCertificate::generate()?;
        Ok(Self {
            tcp_listener,
            server: Arc::new(server),
            certificate: Arc::new(certificate),
        })
    }
}

#[async_trait]
impl ProxyAcceptor for RealityAcceptor {
    type TS = SslStream<PrefixedStream>;
    type US = DummyUdpStream;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        loop {
            let (stream, addr) = self.tcp_listener.accept().await?;
            stream.set_nodelay(true)?;
            log::info!("reality tcp connection from {}", addr);

            match self.handle(stream).await {
                Ok(Some(tls_stream)) => {
                    return Ok(AcceptResult::Tcp((
                        tls_stream,
                        Address::SocketAddress(addr),
                    )));
                }
                Ok(None) => continue,
                Err(error) => {
                    log::debug!("reality connection from {} dropped: {}", addr, error);
                    continue;
                }
            }
        }
    }
}

impl RealityAcceptor {
    /// Returns `Ok(Some(stream))` on successful REALITY auth, `Ok(None)` when the
    /// connection was forwarded to the decoy target, and `Err` for setup errors.
    async fn handle(&self, stream: TcpStream) -> io::Result<Option<SslStream<PrefixedStream>>> {
        let server = self.server.clone();
        let read = timeout(server.handshake_timeout, read_client_hello(stream, &server)).await;
        let (mut stream, record_bytes, message) = match read {
            Ok(Ok(value)) => value,
            Ok(Err(error)) => return Err(error),
            Err(_) => return Err(new_error("reality client hello timed out")),
        };

        match self.authenticate(&message) {
            Some(auth_key) => {
                let prefixed = PrefixedStream::new(record_bytes, stream);
                let tls_stream = self.finish_handshake(prefixed, &auth_key, server).await?;
                Ok(Some(tls_stream))
            }
            None => {
                // Forward the bytes we already consumed, then relay transparently.
                let target = server.target.clone();
                tokio::spawn(async move {
                    if let Err(error) = forward_to_target(&mut stream, record_bytes, &target).await
                    {
                        log::debug!("reality fallback to {} ended: {}", target, error);
                    }
                });
                Ok(None)
            }
        }
    }

    /// Performs REALITY authentication; returns the derived auth key on success.
    fn authenticate(&self, message: &[u8]) -> Option<[u8; crypto::AUTH_KEY_LEN]> {
        let server = &self.server;
        let parsed = client_hello::parse(message).ok()?;
        if !parsed.offers_tls13 {
            return None;
        }
        if !server.server_names.contains(&parsed.server_name) {
            return None;
        }
        let peer_public = parsed.key_share_x25519?;

        let auth_key =
            crypto::derive_auth_key(&server.private_key, &peer_public, &parsed.random[..20])
                .ok()?;

        // AAD is the ClientHello message with the session_id region zeroed.
        let mut aad = message.to_vec();
        let offset = parsed.session_id_offset;
        if offset + crypto::SESSION_ID_LEN > aad.len() {
            return None;
        }
        for byte in &mut aad[offset..offset + crypto::SESSION_ID_LEN] {
            *byte = 0;
        }
        let nonce = &parsed.random[20..32];
        let plain = crypto::open_session_id(&auth_key, nonce, &parsed.session_id, &aad).ok()?;
        let (_version, unix_time, short_id) = crypto::parse_plaintext(&plain);

        if !server.short_ids.contains(&short_id) {
            return None;
        }
        if !time_within_window(unix_time, server.max_time_diff) {
            return None;
        }
        Some(auth_key)
    }

    /// Completes a real TLS 1.3 handshake presenting the forged certificate.
    async fn finish_handshake(
        &self,
        stream: PrefixedStream,
        auth_key: &[u8; crypto::AUTH_KEY_LEN],
        server: Arc<RealityServer>,
    ) -> io::Result<SslStream<PrefixedStream>> {
        let forged_der = self.certificate.forge(auth_key)?;
        let forged = X509::from_der(&forged_der).map_err(new_error)?;

        let mut builder =
            SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).map_err(new_error)?;
        builder
            .set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(new_error)?;
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(new_error)?;
        builder.set_certificate(&forged).map_err(new_error)?;
        builder
            .set_private_key(self.certificate.private_key())
            .map_err(new_error)?;
        let acceptor = builder.build();

        let tls_stream = timeout(
            server.handshake_timeout,
            tokio_boring::accept(&acceptor, stream),
        )
        .await
        .map_err(|_| new_error("reality TLS handshake timed out"))?
        .map_err(new_error)?;
        Ok(tls_stream)
    }
}

/// Reads TLS handshake records until a complete ClientHello message is buffered.
///
/// Returns the stream, the raw record bytes consumed (for replay), and the
/// de-fragmented handshake message (`type || u24_len || body`).
async fn read_client_hello(
    mut stream: TcpStream,
    server: &RealityServer,
) -> io::Result<(TcpStream, Vec<u8>, Vec<u8>)> {
    let mut records = Vec::with_capacity(1024);
    let mut message = Vec::with_capacity(1024);
    let max = server.max_client_hello_size;

    loop {
        // Record header.
        let header_start = records.len();
        read_exact_into(&mut stream, &mut records, TLS_RECORD_HEADER_LEN, max).await?;
        let header = &records[header_start..header_start + TLS_RECORD_HEADER_LEN];
        if header[0] != RECORD_TYPE_HANDSHAKE {
            return Err(new_error("first record is not a TLS handshake"));
        }
        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if record_len == 0 || record_len > 16384 {
            return Err(new_error("invalid TLS record length"));
        }
        let payload_start = records.len();
        read_exact_into(&mut stream, &mut records, record_len, max).await?;
        message.extend_from_slice(&records[payload_start..payload_start + record_len]);

        // Once we have the 4-byte handshake header we know the full length.
        if message.len() >= 4 {
            let body_len =
                ((message[1] as usize) << 16) | ((message[2] as usize) << 8) | message[3] as usize;
            let total = body_len + 4;
            if message.len() >= total {
                message.truncate(total);
                return Ok((stream, records, message));
            }
        }
        if records.len() >= max {
            return Err(new_error("client hello exceeds size limit"));
        }
    }
}

async fn read_exact_into(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    len: usize,
    max: usize,
) -> io::Result<()> {
    if buffer.len() + len > max {
        return Err(new_error("client hello exceeds size limit"));
    }
    let start = buffer.len();
    buffer.resize(start + len, 0);
    stream.read_exact(&mut buffer[start..]).await?;
    Ok(())
}

async fn forward_to_target(
    client: &mut TcpStream,
    consumed: Vec<u8>,
    target: &Address,
) -> io::Result<()> {
    let mut upstream = TcpStream::connect(target.to_string()).await?;
    upstream.set_nodelay(true)?;
    {
        use tokio::io::AsyncWriteExt;
        upstream.write_all(&consumed).await?;
        upstream.flush().await?;
    }
    copy_bidirectional_with_sizes(client, &mut upstream, RELAY_BUFFER_SIZE, RELAY_BUFFER_SIZE)
        .await
        .map(|_| ())
}

fn time_within_window(client_unix: u32, max_diff: Option<Duration>) -> bool {
    let Some(max_diff) = max_diff else {
        return true;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let client = u64::from(client_unix);
    let diff = now.abs_diff(client);
    diff <= max_diff.as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_window_enforced_only_when_configured() {
        assert!(time_within_window(0, None));
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;
        assert!(time_within_window(now, Some(Duration::from_secs(60))));
        assert!(!time_within_window(
            now - 600,
            Some(Duration::from_secs(60))
        ));
    }
}
