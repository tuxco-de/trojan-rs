use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::protocol::ProxyTcpStream;

use super::metrics::{global_metrics, ClientMetrics};

const METRICS_FLUSH_BYTES: u64 = 64 * 1024;
const METRICS_TIME_CHECK_BYTES: u64 = 32 * 1024;
const METRICS_FLUSH_INTERVAL: Duration = Duration::from_secs(1);

enum TrafficDirection {
    Upload,
    Download,
}

pub(crate) struct TrafficMeter {
    client_metrics: Arc<ClientMetrics>,
    direction: TrafficDirection,
    pending_bytes: u64,
    last_flush: Instant,
}

impl TrafficMeter {
    pub(crate) fn upload(client_metrics: Arc<ClientMetrics>) -> Self {
        Self::new(client_metrics, TrafficDirection::Upload)
    }

    pub(crate) fn download(client_metrics: Arc<ClientMetrics>) -> Self {
        Self::new(client_metrics, TrafficDirection::Download)
    }

    fn new(client_metrics: Arc<ClientMetrics>, direction: TrafficDirection) -> Self {
        Self {
            client_metrics,
            direction,
            pending_bytes: 0,
            last_flush: Instant::now(),
        }
    }

    pub(crate) fn record(&mut self, bytes: u64) {
        self.pending_bytes = self.pending_bytes.saturating_add(bytes);
        if self.pending_bytes >= METRICS_FLUSH_BYTES
            || (self.pending_bytes >= METRICS_TIME_CHECK_BYTES
                && self.last_flush.elapsed() >= METRICS_FLUSH_INTERVAL)
        {
            self.flush();
        }
    }

    pub(crate) fn flush(&mut self) {
        if self.pending_bytes == 0 {
            return;
        }

        let bytes = std::mem::take(&mut self.pending_bytes);
        match self.direction {
            TrafficDirection::Upload => {
                self.client_metrics
                    .upload_bytes
                    .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
                global_metrics().add_upload(bytes);
            }
            TrafficDirection::Download => {
                self.client_metrics
                    .download_bytes
                    .fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
                global_metrics().add_download(bytes);
            }
        }
        self.last_flush = Instant::now();
    }
}

impl Drop for TrafficMeter {
    fn drop(&mut self) {
        self.flush();
    }
}

pub struct MeteredStream<S> {
    inner: S,
    upload_meter: TrafficMeter,
    download_meter: TrafficMeter,
}

impl<S> MeteredStream<S> {
    pub fn new(inner: S, client_metrics: Arc<ClientMetrics>) -> Self {
        Self {
            inner,
            upload_meter: TrafficMeter::upload(client_metrics.clone()),
            download_meter: TrafficMeter::download(client_metrics),
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MeteredStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes = (buf.filled().len() - before) as u64;
                this.upload_meter.record(bytes);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MeteredStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(bytes)) => {
                this.download_meter.record(bytes as u64);
                Poll::Ready(Ok(bytes))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_shutdown(cx) {
            Poll::Ready(result) => {
                this.upload_meter.flush();
                this.download_meter.flush();
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: ProxyTcpStream> ProxyTcpStream for MeteredStream<S> {}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;

    use super::{ClientMetrics, TrafficMeter, METRICS_FLUSH_BYTES};

    #[test]
    fn batches_metric_updates_until_the_flush_threshold() {
        let client = Arc::new(ClientMetrics::new(1, "test".to_string()));
        let mut meter = TrafficMeter::upload(client.clone());

        meter.record(METRICS_FLUSH_BYTES - 1);
        assert_eq!(client.upload_bytes.load(Ordering::Relaxed), 0);

        meter.record(1);
        assert_eq!(
            client.upload_bytes.load(Ordering::Relaxed),
            METRICS_FLUSH_BYTES
        );
    }

    #[test]
    fn flushes_the_remaining_bytes_when_the_meter_is_dropped() {
        let client = Arc::new(ClientMetrics::new(1, "test".to_string()));
        {
            let mut meter = TrafficMeter::download(client.clone());
            meter.record(1);
        }
        assert_eq!(client.download_bytes.load(Ordering::Relaxed), 1);
    }
}
