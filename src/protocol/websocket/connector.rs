use super::{default_handshake_timeout_secs, new_error, BinaryWsStream, WebSocketOptions};
use crate::protocol::{DummyUdpStream, ProxyConnector};
use async_trait::async_trait;
use serde::Deserialize;
use std::{io, time::Duration};
use tokio::time::timeout;
use tokio_tungstenite::{
    client_async_with_config,
    tungstenite::http::{StatusCode, Uri},
};

#[derive(Deserialize)]
pub struct WebSocketConnectorConfig {
    uri: String,
    #[serde(default = "default_handshake_timeout_secs")]
    handshake_timeout_secs: u64,
    #[serde(flatten)]
    options: WebSocketOptions,
}

pub struct WebSocketConnector<T: ProxyConnector> {
    uri: Uri,
    handshake_timeout: Duration,
    websocket_config: tokio_tungstenite::tungstenite::protocol::WebSocketConfig,
    inner: T,
}

#[async_trait]
impl<T: ProxyConnector> ProxyConnector for WebSocketConnector<T> {
    type TS = BinaryWsStream<T::TS>;
    type US = DummyUdpStream;

    async fn connect_tcp(&self, addr: &crate::protocol::Address) -> io::Result<Self::TS> {
        let stream = self.inner.connect_tcp(addr).await?;
        let (stream, resp) = timeout(
            self.handshake_timeout,
            client_async_with_config(&self.uri, stream, Some(self.websocket_config)),
        )
        .await
        .map_err(|_| new_error("websocket handshake timed out"))?
        .map_err(new_error)?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err(new_error(format!("bad status: {}", resp.status())));
        }
        let stream = BinaryWsStream::new(stream);
        Ok(stream)
    }

    async fn connect_udp(&self) -> io::Result<Self::US> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "websocket connector does not provide a standalone UDP transport",
        ))
    }
}

impl<T: ProxyConnector> WebSocketConnector<T> {
    pub fn new(config: &WebSocketConnectorConfig, inner: T) -> io::Result<Self> {
        config.validate()?;
        let uri = config.uri.parse().map_err(new_error)?;
        Ok(Self {
            inner,
            uri,
            handshake_timeout: Duration::from_secs(config.handshake_timeout_secs),
            websocket_config: config.options.tungstenite_config(),
        })
    }
}

impl WebSocketConnectorConfig {
    fn validate(&self) -> io::Result<()> {
        if self.handshake_timeout_secs == 0 {
            return Err(new_error("invalid websocket handshake timeout"));
        }
        self.options.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::WebSocketConnectorConfig;

    #[test]
    fn legacy_uri_only_config_uses_safe_defaults() {
        let config: WebSocketConnectorConfig =
            toml::from_str("uri = 'wss://example.com/trojan'").unwrap();
        config.validate().unwrap();
        assert_eq!(config.handshake_timeout_secs, 10);
        assert_eq!(config.options.read_buffer_size, 16 * 1024);
        assert_eq!(config.options.max_message_size, 1024 * 1024);
    }

    #[test]
    fn rejects_zero_handshake_timeout() {
        let config: WebSocketConnectorConfig =
            toml::from_str("uri = 'wss://example.com/trojan'\nhandshake_timeout_secs = 0").unwrap();
        assert!(config.validate().is_err());
    }
}
