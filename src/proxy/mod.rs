pub mod config;
pub mod relay;

use std::{fs::File, io::{self, Read}};
use log::LevelFilter;

use crate::{
    error::Error,
    protocol::{
        direct::connector::DirectConnector,
        mux::{
            acceptor::MuxAcceptor,
            connector::MuxConnector,
        },
        socks5::acceptor::Socks5Acceptor,
        tls::{
            acceptor::TrojanTlsAcceptor,
            connector::TrojanTlsConnector,
        },
        trojan::{
            acceptor::TrojanAcceptor,
            connector::TrojanConnector,
        },
        websocket::{
            acceptor::WebSocketAcceptor,
            connector::WebSocketConnector,
        },
    },
};

use self::config::*;
pub use self::relay::relay_tcp;
use self::relay::run_proxy;

pub async fn launch_from_config_filename(filename: String) -> io::Result<()> {
    let mut file = File::open(filename)?;
    let mut config_string = String::new();
    file.read_to_string(&mut config_string)?;
    launch_from_config_string(config_string).await
}

pub async fn launch_from_config_string(config_string: String) -> io::Result<()> {
    let config: GlobalConfig = toml::from_str(&config_string).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if let Some(log_level) = config.log_level {
        let level = match log_level.as_str() {
            "trace" => LevelFilter::Trace,
            "debug" => LevelFilter::Debug,
            "info" => LevelFilter::Info,
            "warn" => LevelFilter::Warn,
            "error" => LevelFilter::Error,
            _ => {
                return Err(Error::new("invalid log_level").into());
            }
        };
        let _ = env_logger::builder().filter_level(level).try_init();
    } else {
        let _ = env_logger::builder()
            .filter_level(LevelFilter::Debug)
            .try_init();
    }
    match config.mode.as_str() {
        #[cfg(feature = "server")]
        "server" => {
            log::debug!("server mode");
            let config: ServerConfig = toml::from_str(&config_string).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let direct_connector = DirectConnector {};
            
            let tls_acceptor = TrojanTlsAcceptor::new(&config.tls).await?;
            if config.websocket.is_none() {
                let trojan_acceptor = TrojanAcceptor::new(&config.trojan, tls_acceptor)?;
                if config.mux.is_none() {
                    run_proxy(trojan_acceptor, direct_connector).await?;
                } else {
                    let mux_acceptor = MuxAcceptor::new(trojan_acceptor, &config.mux.unwrap())?;
                    run_proxy(mux_acceptor, direct_connector).await?;
                }
            } else {
                let ws_acceptor =
                    WebSocketAcceptor::new(&config.websocket.unwrap(), tls_acceptor)?;
                let trojan_acceptor = TrojanAcceptor::new(&config.trojan, ws_acceptor)?;
                if config.mux.is_none() {
                    run_proxy(trojan_acceptor, direct_connector).await?;
                } else {
                    let mux_acceptor = MuxAcceptor::new(trojan_acceptor, &config.mux.unwrap())?;
                    run_proxy(mux_acceptor, direct_connector).await?;
                }
            }
        }
        #[cfg(feature = "client")]
        "client" => {
            log::debug!("client mode");
            let config: ClientConfig = toml::from_str(&config_string).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let socks5_acceptor = Socks5Acceptor::new(&config.socks5).await?;
            let tls_connector = TrojanTlsConnector::new(&config.tls)?;
            if config.websocket.is_none() {
                let trojan_connector = TrojanConnector::new(&config.trojan, tls_connector)?;
                if config.mux.is_none() {
                    run_proxy(socks5_acceptor, trojan_connector).await?;
                } else {
                    let mux_connector =
                        MuxConnector::new(&config.mux.unwrap(), trojan_connector).unwrap();
                    run_proxy(socks5_acceptor, mux_connector).await?;
                }
            } else {
                let ws_connector =
                    WebSocketConnector::new(&config.websocket.unwrap(), tls_connector)?;
                let trojan_connector = TrojanConnector::new(&config.trojan, ws_connector)?;
                if config.mux.is_none() {
                    run_proxy(socks5_acceptor, trojan_connector).await?;
                } else {
                    let mux_connector =
                        MuxConnector::new(&config.mux.unwrap(), trojan_connector).unwrap();
                    run_proxy(socks5_acceptor, mux_connector).await?;
                }
            }
        }
        _ => {
            log::error!("invalid mode: {}", config.mode.as_str());
        }
    }
    Ok(())
}
