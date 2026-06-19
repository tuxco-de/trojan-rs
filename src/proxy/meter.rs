use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::metrics::{global_metrics, ClientMetrics};

pin_project! {
    pub struct MeteredStream<S> {
        #[pin]
        inner: S,
        client_metrics: Arc<ClientMetrics>,
    }
}

impl<S> MeteredStream<S> {
    pub fn new(inner: S, client_metrics: Arc<ClientMetrics>) -> Self {
        Self {
            inner,
            client_metrics,
        }
    }
}

impl<S: AsyncRead> AsyncRead for MeteredStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();
        let before = buf.filled().len();
        match this.inner.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                let n = (after - before) as u64;
                if n > 0 {
                    this.client_metrics.upload_bytes.fetch_add(n, Ordering::Relaxed);
                    global_metrics().add_upload(n);
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        match this.inner.poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                let bytes = n as u64;
                if bytes > 0 {
                    this.client_metrics.download_bytes.fetch_add(bytes, Ordering::Relaxed);
                    global_metrics().add_download(bytes);
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

use crate::protocol::ProxyTcpStream;
impl<S: ProxyTcpStream> ProxyTcpStream for MeteredStream<S> {}
