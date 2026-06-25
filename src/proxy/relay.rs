use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::io::copy_bidirectional_with_sizes;

use crate::protocol::{
    AcceptResult, Address, ProxyAcceptor, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite,
};
use async_trait::async_trait;
use tokio::net::{TcpStream, UdpSocket};

use super::meter::{MeteredStream, TrafficMeter};
use super::metrics::{global_metrics, ClientMetrics};

const RELAY_BUFFER_SIZE: usize = 0x10000;

async fn copy_udp<R: UdpRead, W: UdpWrite>(
    r: &mut R,
    w: &mut W,
    mut meter: Option<&mut TrafficMeter>,
) -> io::Result<()> {
    let mut buf = [0u8; RELAY_BUFFER_SIZE];
    loop {
        let (len, addr) = r.read_from(&mut buf).await?;
        log::debug!("udp packet addr={} len={}", addr, len);
        w.write_to(&buf[..len], &addr).await?;
        if let Some(meter) = meter.as_deref_mut() {
            meter.record(len as u64);
        }
    }
}

async fn relay_udp_metered<T: ProxyUdpStream, U: ProxyUdpStream>(
    a: T,
    b: U,
    client_metrics: Arc<ClientMetrics>,
) {
    relay_udp_with_meters(
        a,
        b,
        Some(TrafficMeter::upload(client_metrics.clone())),
        Some(TrafficMeter::download(client_metrics)),
    )
    .await;
}

async fn relay_udp_with_meters<T: ProxyUdpStream, U: ProxyUdpStream>(
    a: T,
    b: U,
    mut upload_meter: Option<TrafficMeter>,
    mut download_meter: Option<TrafficMeter>,
) {
    let (mut a_rx, mut a_tx) = a.split();
    let (mut b_rx, mut b_tx) = b.split();
    let t1 = copy_udp(&mut a_rx, &mut b_tx, upload_meter.as_mut());
    let t2 = copy_udp(&mut b_rx, &mut a_tx, download_meter.as_mut());
    let e = tokio::select! {
        e = t1 => {e}
        e = t2 => {e}
    };
    if let Err(e) = e {
        log::debug!("udp_relay err: {}", e)
    }
    let _ = T::reunite(a_rx, a_tx).close().await;
    let _ = U::reunite(b_rx, b_tx).close().await;
    log::info!("udp session ends");
}

pub async fn relay_tcp<T: ProxyTcpStream, U: ProxyTcpStream>(mut a: T, mut b: U) {
    if let Err(e) =
        copy_bidirectional_with_sizes(&mut a, &mut b, RELAY_BUFFER_SIZE, RELAY_BUFFER_SIZE).await
    {
        log::debug!("relay_tcp err: {}", e)
    }
    log::info!("tcp session ends");
}

#[derive(Clone)]
pub struct DirectUdpStream {
    inner: Arc<UdpSocket>,
    resolved_addresses: Arc<Mutex<HashMap<Address, SocketAddr>>>,
}

impl DirectUdpStream {
    async fn resolve_address(&self, address: &Address) -> io::Result<SocketAddr> {
        if let Address::SocketAddress(address) = address {
            return Ok(*address);
        }

        if let Some(address) = self
            .resolved_addresses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(address)
            .copied()
        {
            return Ok(address);
        }

        let Address::DomainNameAddress(domain, port) = address else {
            unreachable!();
        };
        let resolved = tokio::net::lookup_host((domain.as_str(), *port))
            .await?
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::AddrNotAvailable, "no address found"))?;

        self.resolved_addresses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(address.clone(), resolved);
        Ok(resolved)
    }
}

#[async_trait]
impl UdpRead for DirectUdpStream {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let (len, addr) = self.inner.recv_from(buf).await?;
        Ok((len, Address::SocketAddress(addr)))
    }
}

#[async_trait]
impl UdpWrite for DirectUdpStream {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> io::Result<()> {
        let addr = self.resolve_address(addr).await?;
        let _ = self.inner.send_to(buf, addr).await?;
        Ok(())
    }
}

#[async_trait]
impl ProxyUdpStream for DirectUdpStream {
    type R = Self;
    type W = Self;

    fn split(self) -> (Self::R, Self::W) {
        (self.clone(), self)
    }

    fn reunite(r: Self::R, _: Self::W) -> Self {
        r
    }

    async fn close(self) -> io::Result<()> {
        Ok(())
    }
}

pub async fn run_proxy<I: ProxyAcceptor>(acceptor: I) -> io::Result<()> {
    loop {
        match acceptor.accept().await {
            Ok(AcceptResult::Tcp((inbound, addr))) => {
                let metrics = global_metrics();
                let client_id = metrics.generate_id();
                let client_metrics = Arc::new(ClientMetrics::new(client_id, addr.to_string()));
                metrics.add_client(client_metrics.clone()).await;

                let metered_inbound = MeteredStream::new(inbound, client_metrics);

                tokio::spawn(async move {
                    match TcpStream::connect(addr.to_string()).await {
                        Ok(outbound) => {
                            if let Err(e) = outbound.set_nodelay(true) {
                                log::debug!("failed to enable TCP_NODELAY for {}: {}", addr, e);
                            }
                            log::info!("relaying tcp stream to {}", addr);
                            relay_tcp(metered_inbound, outbound).await;
                        }
                        Err(e) => {
                            log::error!("failed to relay tcp stream to {}: {}", addr, e);
                        }
                    }
                    global_metrics().remove_client(client_id).await;
                });
            }
            Ok(AcceptResult::Udp(inbound)) => {
                let metrics = global_metrics();
                let client_id = metrics.generate_id();
                let client_metrics = Arc::new(ClientMetrics::new(client_id, "UDP".to_string()));
                metrics.add_client(client_metrics.clone()).await;

                tokio::spawn(async move {
                    match UdpSocket::bind(":::0").await {
                        Ok(socket) => {
                            log::info!("relaying udp stream..");
                            let outbound = DirectUdpStream {
                                inner: Arc::new(socket),
                                resolved_addresses: Arc::new(Mutex::new(HashMap::new())),
                            };
                            relay_udp_metered(inbound, outbound, client_metrics).await;
                        }
                        Err(e) => {
                            log::error!("failed to relay udp stream: {}", e);
                        }
                    }
                    global_metrics().remove_client(client_id).await;
                });
            }
            Err(e) => {
                log::error!("accept failed: {}", e);
            }
        }
    }
}
