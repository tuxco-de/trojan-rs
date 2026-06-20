pub mod config;
pub mod relay;
pub mod metrics;
pub mod meter;

use log::LevelFilter;
use std::{
    fs::File,
    io::{self, Read},
};

use crate::{
    error::Error,
    protocol::{
        mux::acceptor::MuxAcceptor,
        singbox_mux::SingBoxMuxAcceptor,
        tls::acceptor::{AlpnFallbackAcceptor, TrojanTlsAcceptor},
        trojan::acceptor::TrojanAcceptor,
        vless::acceptor::VlessAcceptor,
        websocket::acceptor::WebSocketAcceptor,
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
    if config.mode.as_str() != "server" {
        return Err(Error::new(format!("invalid mode: {}", config.mode.as_str())).into());
    }

    log::debug!("server mode");
    let config: ServerConfig = toml::from_str(&config_string)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    let fallback_config = config.fallback.as_ref();
    let tls_acceptor = AlpnFallbackAcceptor::new(
        fallback_config,
        TrojanTlsAcceptor::new(&config.tls, fallback_config.is_some()).await?,
    )?;

    macro_rules! start_proxy {
        ($acceptor:expr, $config:expr) => {
            if let Some(mux) = &$config.mux {
                let mux_acceptor = MuxAcceptor::new($acceptor, mux)?;
                run_proxy(mux_acceptor).await?;
            } else {
                run_proxy($acceptor).await?;
            }
        };
    }

    match (config.trojan, config.vless) {
        (Some(trojan), None) => {
            if let Some(websocket) = config.websocket {
                let ws_acceptor =
                    WebSocketAcceptor::new(&websocket, fallback_config, tls_acceptor)?;
                let trojan_acceptor =
                    TrojanAcceptor::new(&trojan, fallback_config, ws_acceptor)?;
                start_proxy!(trojan_acceptor, config);
            } else {
                let trojan_acceptor =
                    TrojanAcceptor::new(&trojan, fallback_config, tls_acceptor)?;
                start_proxy!(trojan_acceptor, config);
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
            let sing_box_mux_enabled = vless.sing_box_mux_enabled();
            let vless_acceptor = VlessAcceptor::new(&vless, ws_acceptor)?;
            if sing_box_mux_enabled {
                run_proxy(SingBoxMuxAcceptor::new(vless_acceptor)).await?;
            } else {
                run_proxy(vless_acceptor).await?;
            }
        }
        (Some(_), Some(_)) => {
            return Err(Error::new("configure either [trojan] or [vless], not both").into());
        }
        (None, None) => {
            return Err(Error::new("server requires [trojan] or [vless]").into());
        }
    }
    Ok(())
}
