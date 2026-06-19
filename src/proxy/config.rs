use crate::protocol::{
    fallback::FallbackConfig,
    mux::acceptor::MuxAcceptorConfig,
    tls::acceptor::TrojanTlsAcceptorConfig,
    trojan::acceptor::TrojanAcceptorConfig,
    vless::acceptor::VlessAcceptorConfig,
    websocket::acceptor::WebSocketAcceptorConfig,
};
use serde::Deserialize;

#[derive(Deserialize)]
pub struct GlobalConfig {
    pub mode: String,
    pub log_level: Option<String>,
}

#[derive(Deserialize)]
pub struct ServerConfig {
    pub trojan: Option<TrojanAcceptorConfig>,
    pub vless: Option<VlessAcceptorConfig>,
    pub tls: TrojanTlsAcceptorConfig,
    pub fallback: Option<FallbackConfig>,
    pub websocket: Option<WebSocketAcceptorConfig>,
    pub mux: Option<MuxAcceptorConfig>,
}
