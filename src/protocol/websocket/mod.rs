pub mod acceptor;

use bytes::{Buf, Bytes};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{interval_at, Duration, Instant, Interval, MissedTickBehavior},
};
use tokio_tungstenite::{
    tungstenite::{protocol::WebSocketConfig, Error as WebSocketError, Message},
    WebSocketStream,
};

use crate::error::Error;
use futures_core::{ready, Stream};
use futures_util::sink::Sink;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use super::ProxyTcpStream;

const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
const DEFAULT_MAX_HANDSHAKE_SIZE: usize = 8 * 1024;
const DEFAULT_BUFFER_SIZE: usize = 16 * 1024;
const DEFAULT_MAX_MESSAGE_SIZE: usize = 1024 * 1024;
const DEFAULT_MAX_WRITE_BUFFER_SIZE: usize = 2 * 1024 * 1024;
const DEFAULT_MAX_EARLY_DATA: usize = 8 * 1024;
const DEFAULT_KEEPALIVE_INTERVAL_SECS: u64 = 30;

pub(super) fn default_handshake_timeout_secs() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_SECS
}

pub(super) fn default_max_handshake_size() -> usize {
    DEFAULT_MAX_HANDSHAKE_SIZE
}

pub(super) fn default_max_early_data() -> usize {
    DEFAULT_MAX_EARLY_DATA
}

fn default_buffer_size() -> usize {
    DEFAULT_BUFFER_SIZE
}

fn default_max_message_size() -> usize {
    DEFAULT_MAX_MESSAGE_SIZE
}

fn default_max_write_buffer_size() -> usize {
    DEFAULT_MAX_WRITE_BUFFER_SIZE
}

fn default_keepalive_interval_secs() -> u64 {
    DEFAULT_KEEPALIVE_INTERVAL_SECS
}

#[derive(Clone, Copy, Debug, Deserialize)]
pub(super) struct WebSocketOptions {
    #[serde(default = "default_buffer_size")]
    pub read_buffer_size: usize,
    #[serde(default = "default_buffer_size")]
    pub write_buffer_size: usize,
    #[serde(default = "default_max_message_size")]
    pub max_message_size: usize,
    #[serde(default = "default_max_message_size")]
    pub max_frame_size: usize,
    #[serde(default = "default_max_write_buffer_size")]
    pub max_write_buffer_size: usize,
    #[serde(default)]
    pub max_write_frame_size: usize,
    #[serde(default = "default_keepalive_interval_secs")]
    pub keepalive_interval_secs: u64,
}

impl WebSocketOptions {
    pub fn validate(&self) -> io::Result<()> {
        if self.read_buffer_size == 0
            || self.max_message_size == 0
            || self.max_frame_size == 0
            || self.max_frame_size > self.max_message_size
            || self.max_write_buffer_size <= self.write_buffer_size
            || self.max_write_frame_size > self.max_message_size
        {
            return Err(new_error("invalid websocket resource limits"));
        }
        Ok(())
    }

    pub fn tungstenite_config(&self) -> WebSocketConfig {
        WebSocketConfig::default()
            .read_buffer_size(self.read_buffer_size)
            .write_buffer_size(self.write_buffer_size)
            .max_write_buffer_size(self.max_write_buffer_size)
            .max_message_size(Some(self.max_message_size))
            .max_frame_size(Some(self.max_frame_size))
    }
}

fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("websocket: {}", message.to_string())).into()
}

pub struct BinaryWsStream<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> {
    inner: WebSocketStream<T>,
    read_buffer: Option<Bytes>,
    read_closed: bool,
    close_flushed: bool,
    keepalive: Option<Interval>,
    keepalive_state: KeepaliveState,
    max_write_frame_size: usize,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> ProxyTcpStream for BinaryWsStream<T> {}

enum KeepaliveState {
    Idle,
    ReadyToSend,
    Flushing,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncRead for BinaryWsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            ready!(self.poll_keepalive(cx))?;
            if self.read_closed {
                if self.close_flushed {
                    return Poll::Ready(Ok(()));
                }
                return match Pin::new(&mut self.inner).poll_flush(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Ok(()))
                    | Poll::Ready(Err(
                        WebSocketError::ConnectionClosed | WebSocketError::AlreadyClosed,
                    )) => {
                        self.close_flushed = true;
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Err(error)) => {
                        self.close_flushed = true;
                        Poll::Ready(Err(new_error(error)))
                    }
                };
            }
            if let Some(read_buffer) = &mut self.read_buffer {
                if read_buffer.len() <= buf.remaining() {
                    buf.put_slice(read_buffer);
                    self.read_buffer = None;
                } else {
                    let len = buf.remaining();
                    buf.put_slice(&read_buffer[..len]);
                    read_buffer.advance(len);
                }
                return Poll::Ready(Ok(()));
            }
            let message = ready!(Pin::new(&mut self.inner).poll_next(cx));
            if message.is_none() {
                self.read_closed = true;
                self.close_flushed = true;
                continue;
            }
            let message = message.unwrap().map_err(new_error)?;
            match message {
                Message::Binary(binary) => {
                    if binary.is_empty() {
                        continue;
                    }
                    if binary.len() <= buf.remaining() {
                        buf.put_slice(&binary);
                        return Poll::Ready(Ok(()));
                    } else {
                        self.read_buffer = Some(binary);
                        continue;
                    }
                }
                Message::Close(_) => {
                    self.read_closed = true;
                    continue;
                }
                Message::Ping(_) | Message::Pong(_) => continue,
                _ => {
                    return Poll::Ready(Err(new_error(
                        "websocket transport only supports binary messages",
                    )))
                }
            }
        }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncWrite for BinaryWsStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(self.poll_keepalive(cx))?;
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(new_error)?;
        let length = if self.max_write_frame_size == 0 {
            buf.len()
        } else {
            buf.len().min(self.max_write_frame_size)
        };
        let message = Message::Binary(Bytes::copy_from_slice(&buf[..length]));
        Pin::new(&mut self.inner)
            .start_send(message)
            .map_err(new_error)?;
        Poll::Ready(Ok(length))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        ready!(self.poll_keepalive(cx))?;
        let inner = Pin::new(&mut self.inner);
        inner.poll_flush(cx).map_err(new_error)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_close(cx).map_err(new_error)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> BinaryWsStream<T> {
    #[cfg(test)]
    pub fn new(inner: WebSocketStream<T>) -> Self {
        Self::new_with_options(inner, Bytes::new(), 0, 0)
    }

    pub fn new_with_options(
        inner: WebSocketStream<T>,
        early_data: Bytes,
        keepalive_interval_secs: u64,
        max_write_frame_size: usize,
    ) -> Self {
        let keepalive = if keepalive_interval_secs == 0 {
            None
        } else {
            let mut interval = interval_at_next_tick(Duration::from_secs(keepalive_interval_secs));
            interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
            Some(interval)
        };
        Self {
            inner,
            read_buffer: (!early_data.is_empty()).then_some(early_data),
            read_closed: false,
            close_flushed: false,
            keepalive,
            keepalive_state: KeepaliveState::Idle,
            max_write_frame_size,
        }
    }

    fn poll_keepalive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.keepalive.is_none() {
            return Poll::Ready(Ok(()));
        }
        loop {
            match self.keepalive_state {
                KeepaliveState::Idle => {
                    let keepalive = self.keepalive.as_mut().unwrap();
                    if Pin::new(keepalive).poll_tick(cx).is_pending() {
                        return Poll::Ready(Ok(()));
                    }
                    self.keepalive_state = KeepaliveState::ReadyToSend;
                }
                KeepaliveState::ReadyToSend => {
                    ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(new_error)?;
                    Pin::new(&mut self.inner)
                        .start_send(Message::Ping(Bytes::new()))
                        .map_err(new_error)?;
                    self.keepalive_state = KeepaliveState::Flushing;
                }
                KeepaliveState::Flushing => {
                    ready!(Pin::new(&mut self.inner).poll_flush(cx)).map_err(new_error)?;
                    self.keepalive_state = KeepaliveState::Idle;
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

fn interval_at_next_tick(period: Duration) -> Interval {
    interval_at(Instant::now() + period, period)
}

#[cfg(test)]
mod tests {
    use super::{BinaryWsStream, WebSocketOptions};
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio_tungstenite::{
        tungstenite::{protocol::Role, Message},
        WebSocketStream,
    };

    async fn websocket_pair() -> (BinaryWsStream<DuplexStream>, WebSocketStream<DuplexStream>) {
        let (server, client) = tokio::io::duplex(4096);
        let server = WebSocketStream::from_raw_socket(server, Role::Server, None).await;
        let client = WebSocketStream::from_raw_socket(client, Role::Client, None).await;
        (BinaryWsStream::new(server), client)
    }

    #[tokio::test]
    async fn ignores_control_frames_and_reads_binary_data() {
        let (mut server, mut client) = websocket_pair().await;
        client
            .send(Message::Ping(Bytes::from_static(b"ping")))
            .await
            .unwrap();
        client
            .send(Message::Binary(Bytes::from_static(b"payload")))
            .await
            .unwrap();

        let mut payload = [0u8; 7];
        server.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"payload");

        assert!(matches!(client.next().await, Some(Ok(Message::Pong(_)))));
    }

    #[tokio::test]
    async fn close_frame_is_exposed_as_eof() {
        let (mut server, mut client) = websocket_pair().await;
        client.close(None).await.unwrap();

        let mut byte = [0u8; 1];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn shutdown_sends_a_close_frame() {
        let (mut server, mut client) = websocket_pair().await;

        let server_task = async move {
            server.shutdown().await.unwrap();
        };
        let client_task = async move {
            assert!(matches!(client.next().await, Some(Ok(Message::Close(_)))));
        };

        tokio::join!(server_task, client_task);
    }

    #[tokio::test]
    async fn splits_writes_by_configured_frame_size() {
        let (server, mut client) = websocket_pair().await;
        let mut server = BinaryWsStream::new_with_options(server.inner, Bytes::new(), 0, 3);

        server.write_all(b"abcdef").await.unwrap();
        server.flush().await.unwrap();

        assert!(matches!(
            client.next().await,
            Some(Ok(Message::Binary(payload))) if &payload[..] == b"abc"
        ));
        assert!(matches!(
            client.next().await,
            Some(Ok(Message::Binary(payload))) if &payload[..] == b"def"
        ));
    }

    #[tokio::test]
    async fn sends_keepalive_ping() {
        let (server, mut client) = websocket_pair().await;
        let mut server = BinaryWsStream::new_with_options(server.inner, Bytes::new(), 1, 0);
        let mut one_byte = [0u8; 1];

        let server_task = tokio::spawn(async move {
            let _ = tokio::time::timeout(
                std::time::Duration::from_millis(1500),
                server.read(&mut one_byte),
            )
            .await;
        });
        let message = tokio::time::timeout(std::time::Duration::from_secs(2), client.next())
            .await
            .unwrap();
        server_task.abort();

        assert!(matches!(message, Some(Ok(Message::Ping(_)))));
    }

    #[test]
    fn websocket_options_keep_legacy_defaults() {
        let options: WebSocketOptions = toml::from_str("").unwrap();
        options.validate().unwrap();
        assert_eq!(options.read_buffer_size, 16 * 1024);
        assert_eq!(options.max_message_size, 1024 * 1024);
        assert_eq!(options.keepalive_interval_secs, 30);
    }
}
