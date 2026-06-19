pub mod config;
pub mod relay;

use log::LevelFilter;
use std::{
    fs::File,
    io::{self, Read},
};

use crate::{
    error::Error,
    protocol::{
        direct::connector::DirectConnector,
        mux::{acceptor::MuxAcceptor, connector::MuxConnector},
        reality::RealityAcceptor,
        socks5::acceptor::Socks5Acceptor,
        tls::{acceptor::TrojanTlsAcceptor, connector::TrojanTlsConnector, TlsAlpn},
        trojan::{acceptor::TrojanAcceptor, connector::TrojanConnector},
        vless::acceptor::VlessAcceptor,
        websocket::{acceptor::WebSocketAcceptor, connector::WebSocketConnector},
    },
};

use self::config::*;
use self::relay::run_proxy;

pub async fn launch_from_config_filename(filename: String) -> io::Result<()> {
    let mut file = File::open(filename)?;
    let mut config_string = String::new();
    file.read_to_string(&mut config_string)?;
    launch_from_config_string(config_string).await
}

pub async fn launch_from_config_string(config_string: String) -> io::Result<()> {
    let config: GlobalConfig = toml::from_str(&config_string)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
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
            let config: ServerConfig = toml::from_str(&config_string)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let direct_connector = DirectConnector {};

            if let Some(reality) = config.reality {
                if config.tls.is_some() {
                    return Err(Error::new("configure either [tls] or [reality], not both").into());
                }
                if config.trojan.is_some() {
                    return Err(Error::new("REALITY server currently supports VLESS only").into());
                }
                if config.websocket.is_some() {
                    return Err(Error::new("REALITY does not support [websocket]").into());
                }
                if config.mux.is_some() {
                    return Err(Error::new("REALITY does not support [mux]").into());
                }
                let vless = config
                    .vless
                    .ok_or_else(|| Error::new("REALITY server requires [vless]"))?;
                let reality_server = reality.validate()?;
                let reality_acceptor = RealityAcceptor::new(reality_server).await?;
                let vless_acceptor = VlessAcceptor::new(&vless, reality_acceptor)?;
                run_proxy(vless_acceptor, direct_connector).await?;
                return Ok(());
            }

            let tls_config = config
                .tls
                .ok_or_else(|| Error::new("server requires [tls] or [reality]"))?;
            let tls_acceptor = TrojanTlsAcceptor::new(&tls_config).await?;
            let fallback_config = config.fallback.as_ref();
            match (config.trojan, config.vless) {
                (Some(trojan), None) => {
                    if let Some(websocket) = config.websocket {
                        let ws_acceptor =
                            WebSocketAcceptor::new(&websocket, fallback_config, tls_acceptor)?;
                        let trojan_acceptor =
                            TrojanAcceptor::new(&trojan, fallback_config, ws_acceptor)?;
                        if let Some(mux) = config.mux {
                            let mux_acceptor = MuxAcceptor::new(trojan_acceptor, &mux)?;
                            run_proxy(mux_acceptor, direct_connector).await?;
                        } else {
                            run_proxy(trojan_acceptor, direct_connector).await?;
                        }
                    } else {
                        let trojan_acceptor =
                            TrojanAcceptor::new(&trojan, fallback_config, tls_acceptor)?;
                        if let Some(mux) = config.mux {
                            let mux_acceptor = MuxAcceptor::new(trojan_acceptor, &mux)?;
                            run_proxy(mux_acceptor, direct_connector).await?;
                        } else {
                            run_proxy(trojan_acceptor, direct_connector).await?;
                        }
                    }
                }
                (None, Some(vless)) => {
                    if config.mux.is_some() {
                        return Err(Error::new("VLESS does not support trojan-go mux").into());
                    }
                    let websocket = config.websocket.ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "VLESS server requires [websocket]",
                        )
                    })?;
                    let ws_acceptor =
                        WebSocketAcceptor::new_strict(&websocket, fallback_config, tls_acceptor)?;
                    let vless_acceptor = VlessAcceptor::new(&vless, ws_acceptor)?;
                    run_proxy(vless_acceptor, direct_connector).await?;
                }
                (Some(_), Some(_)) => {
                    return Err(Error::new("configure either [trojan] or [vless], not both").into());
                }
                (None, None) => {
                    return Err(Error::new("server requires [trojan] or [vless]").into());
                }
            }
        }
        #[cfg(feature = "client")]
        "client" => {
            log::debug!("client mode");
            let config: ClientConfig = toml::from_str(&config_string)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            let socks5_acceptor = Socks5Acceptor::new(&config.socks5).await?;
            let tls_alpn = if config.websocket.is_some() {
                TlsAlpn::Http11
            } else {
                TlsAlpn::None
            };
            let tls_connector = TrojanTlsConnector::new(&config.tls, tls_alpn)?;
            if let Some(ws_config) = &config.websocket {
                let ws_connector = WebSocketConnector::new(ws_config, tls_connector)?;
                let trojan_connector = TrojanConnector::new(&config.trojan, ws_connector)?;
                if let Some(mux_config) = &config.mux {
                    let mux_connector = MuxConnector::new(mux_config, trojan_connector).unwrap();
                    run_proxy(socks5_acceptor, mux_connector).await?;
                } else {
                    run_proxy(socks5_acceptor, trojan_connector).await?;
                }
            } else {
                let trojan_connector = TrojanConnector::new(&config.trojan, tls_connector)?;
                if let Some(mux_config) = &config.mux {
                    let mux_connector = MuxConnector::new(mux_config, trojan_connector).unwrap();
                    run_proxy(socks5_acceptor, mux_connector).await?;
                } else {
                    run_proxy(socks5_acceptor, trojan_connector).await?;
                }
            }
        }
        _ => {
            log::error!("invalid mode: {}", config.mode.as_str());
        }
    }
    Ok(())
}
