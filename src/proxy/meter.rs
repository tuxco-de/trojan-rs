use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::protocol::{ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite};

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
                    this.client_metrics
                        .upload_bytes
                        .fetch_add(n, Ordering::Relaxed);
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
                    this.client_metrics
                        .download_bytes
                        .fetch_add(bytes, Ordering::Relaxed);
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

impl<S: ProxyTcpStream> ProxyTcpStream for MeteredStream<S> {}

pub struct MeteredUdpStream<S> {
    inner: S,
    client_metrics: Arc<ClientMetrics>,
}

impl<S> MeteredUdpStream<S> {
    pub fn new(inner: S, client_metrics: Arc<ClientMetrics>) -> Self {
        Self {
            inner,
            client_metrics,
        }
    }
}

pub struct MeteredUdpRead<R> {
    inner: R,
    client_metrics: Arc<ClientMetrics>,
}

pub struct MeteredUdpWrite<W> {
    inner: W,
    client_metrics: Arc<ClientMetrics>,
}

#[async_trait::async_trait]
impl<R: UdpRead> UdpRead for MeteredUdpRead<R> {
    async fn read_from(
        &mut self,
        buf: &mut [u8],
    ) -> std::io::Result<(usize, crate::protocol::Address)> {
        let (len, addr) = self.inner.read_from(buf).await?;
        if len > 0 {
            let bytes = len as u64;
            self.client_metrics
                .upload_bytes
                .fetch_add(bytes, Ordering::Relaxed);
            global_metrics().add_upload(bytes);
        }
        Ok((len, addr))
    }
}

#[async_trait::async_trait]
impl<W: UdpWrite> UdpWrite for MeteredUdpWrite<W> {
    async fn write_to(
        &mut self,
        buf: &[u8],
        addr: &crate::protocol::Address,
    ) -> std::io::Result<()> {
        self.inner.write_to(buf, addr).await?;
        if !buf.is_empty() {
            let bytes = buf.len() as u64;
            self.client_metrics
                .download_bytes
                .fetch_add(bytes, Ordering::Relaxed);
            global_metrics().add_download(bytes);
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl<S: ProxyUdpStream> ProxyUdpStream for MeteredUdpStream<S> {
    type R = MeteredUdpRead<S::R>;
    type W = MeteredUdpWrite<S::W>;

    fn split(self) -> (Self::R, Self::W) {
        let (reader, writer) = self.inner.split();
        (
            MeteredUdpRead {
                inner: reader,
                client_metrics: self.client_metrics.clone(),
            },
            MeteredUdpWrite {
                inner: writer,
                client_metrics: self.client_metrics,
            },
        )
    }

    fn reunite(r: Self::R, w: Self::W) -> Self {
        Self {
            inner: S::reunite(r.inner, w.inner),
            client_metrics: r.client_metrics,
        }
    }

    async fn close(self) -> std::io::Result<()> {
        self.inner.close().await
    }
}
