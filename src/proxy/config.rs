use crate::protocol::{
    fallback::FallbackConfig,
    mux::{acceptor::MuxAcceptorConfig, connector::MuxConnectorConfig},
    reality::RealityAcceptorConfig,
    socks5::acceptor::Socks5AcceptorConfig,
    tls::{acceptor::TrojanTlsAcceptorConfig, connector::TrojanTlsConnectorConfig},
    trojan::{acceptor::TrojanAcceptorConfig, connector::TrojanConnectorConfig},
    vless::acceptor::VlessAcceptorConfig,
    websocket::{acceptor::WebSocketAcceptorConfig, connector::WebSocketConnectorConfig},
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct GlobalConfig {
    pub mode: String,
    pub log_level: Option<String>,
}

#[derive(Deserialize)]
pub struct ClientConfig {
    pub socks5: Socks5AcceptorConfig,
    pub trojan: TrojanConnectorConfig,
    pub tls: TrojanTlsConnectorConfig,
    pub websocket: Option<WebSocketConnectorConfig>,
    pub mux: Option<MuxConnectorConfig>,
}

#[derive(Deserialize)]
pub struct ServerConfig {
    pub trojan: Option<TrojanAcceptorConfig>,
    pub vless: Option<VlessAcceptorConfig>,
    pub tls: Option<TrojanTlsAcceptorConfig>,
    pub reality: Option<RealityAcceptorConfig>,
    pub fallback: Option<FallbackConfig>,
    pub websocket: Option<WebSocketAcceptorConfig>,
    pub mux: Option<MuxAcceptorConfig>,
}
