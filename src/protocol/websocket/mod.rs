pub mod acceptor;
pub mod connector;

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_tungstenite::{
    tungstenite::{Error as WebSocketError, Message},
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

fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("websocket: {}", message.to_string())).into()
}

pub struct BinaryWsStream<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> {
    inner: WebSocketStream<T>,
    read_buffer: Option<Bytes>,
    read_closed: bool,
    close_flushed: bool,
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> ProxyTcpStream for BinaryWsStream<T> {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> AsyncRead for BinaryWsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
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
                    return Poll::Ready(Err(new_error(format!(
                        "invalid message type {:?}",
                        message
                    ))))
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
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(new_error)?;
        let message = Message::Binary(Bytes::copy_from_slice(buf));
        Pin::new(&mut self.inner)
            .start_send(message)
            .map_err(new_error)?;
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let inner = Pin::new(&mut self.inner);
        inner.poll_flush(cx).map_err(new_error)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        ready!(Pin::new(&mut self.inner).poll_ready(cx)).map_err(new_error)?;
        let message = Message::Close(None);
        let _ = Pin::new(&mut self.inner).start_send(message);

        let inner = Pin::new(&mut self.inner);
        inner.poll_close(cx).map_err(new_error)
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin + Send + Sync> BinaryWsStream<T> {
    pub fn new(inner: WebSocketStream<T>) -> Self {
        Self {
            inner,
            read_buffer: None,
            read_closed: false,
            close_flushed: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BinaryWsStream;
    use bytes::Bytes;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, DuplexStream};
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
}
