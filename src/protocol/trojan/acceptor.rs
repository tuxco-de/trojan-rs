use async_trait::async_trait;
use bytes::Buf;
use serde::Deserialize;
use std::io;

use crate::protocol::fallback::{FallbackConfig, FallbackPage};
use crate::protocol::{trojan::RequestHeader, AcceptResult, ProxyAcceptor};

use super::{new_error, password_to_hash, TrojanUdpStream, HASH_STR_LEN};

#[derive(Deserialize)]
pub struct TrojanAcceptorConfig {
    password: String,
}

pub struct TrojanAcceptor<T: ProxyAcceptor> {
    valid_hash: [u8; HASH_STR_LEN],
    fallback: Option<FallbackPage>,
    inner: T,
}

#[async_trait]
impl<T: ProxyAcceptor> ProxyAcceptor for TrojanAcceptor<T> {
    type TS = T::TS;
    type US = TrojanUdpStream<T::TS>;
    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        loop {
            let (mut stream, addr) = self.inner.accept().await?.unwrap_tcp_with_addr();
            let mut first_packet = Vec::new();
            match RequestHeader::read_from(&mut stream, &self.valid_hash, &mut first_packet).await {
                Ok(header) => match header {
                    RequestHeader::TcpConnect(_, addr) => {
                        log::info!("trojan tcp stream {}", addr);
                        return Ok(AcceptResult::Tcp((stream, addr)));
                    }
                    RequestHeader::UdpAssociate(_) => {
                        log::info!("trojan udp stream {}", addr);
                        return Ok(AcceptResult::Udp(TrojanUdpStream::new(stream)));
                    }
                },
                Err(e) => {
                    log::debug!("first packet {:x?}", first_packet);
                    if let Some(ref fallback) = self.fallback {
                        log::warn!("invalid trojan request from {}, serving fallback page", addr);
                        fallback.serve(stream, first_packet);
                        continue;
                    }
                    log::warn!("invalid trojan request from {}, no fallback configured", addr);
                    return Err(new_error(format!("invalid packet: {}", e)));
                }
            }
        }
    }
}

impl<T: ProxyAcceptor> TrojanAcceptor<T> {
    pub fn new(
        config: &TrojanAcceptorConfig,
        fallback_config: Option<&FallbackConfig>,
        inner: T,
    ) -> io::Result<Self> {
        let fallback = FallbackPage::new(fallback_config)?;
        let mut valid_hash = [0u8; HASH_STR_LEN];
        password_to_hash(&config.password)
            .as_bytes()
            .copy_to_slice(&mut valid_hash);
        Ok(Self {
            fallback,
            valid_hash,
            inner,
        })
    }
}
