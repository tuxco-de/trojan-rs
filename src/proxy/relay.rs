use std::{io, sync::Arc};
use tokio::io::copy_bidirectional_with_sizes;

use crate::protocol::{
    AcceptResult, ProxyAcceptor, ProxyConnector, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite,
};

const RELAY_BUFFER_SIZE: usize = 0x4000;

async fn copy_udp<R: UdpRead, W: UdpWrite>(r: &mut R, w: &mut W) -> io::Result<()> {
    let mut buf = [0u8; RELAY_BUFFER_SIZE];
    loop {
        let (len, addr) = r.read_from(&mut buf).await?;
        log::debug!("udp packet addr={} len={}", addr, len);
        if len == 0 {
            break;
        }
        w.write_to(&buf[..len], &addr).await?;
    }
    Ok(())
}

pub async fn relay_udp<T: ProxyUdpStream, U: ProxyUdpStream>(a: T, b: U) {
    let (mut a_rx, mut a_tx) = a.split();
    let (mut b_rx, mut b_tx) = b.split();
    let t1 = copy_udp(&mut a_rx, &mut b_tx);
    let t2 = copy_udp(&mut b_rx, &mut a_tx);
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

pub async fn run_proxy<I: ProxyAcceptor, O: ProxyConnector + 'static>(
    acceptor: I,
    connector: O,
) -> io::Result<()> {
    let connector = Arc::new(connector);
    loop {
        match acceptor.accept().await {
            Ok(AcceptResult::Tcp((inbound, addr))) => {
                let connector = connector.clone();
                tokio::spawn(async move {
                    match connector.connect_tcp(&addr).await {
                        Ok(outbound) => {
                            log::info!("relaying tcp stream to {}", addr);
                            relay_tcp(inbound, outbound).await;
                        }
                        Err(e) => {
                            log::error!("failed to relay tcp stream to {}: {}", addr, e);
                        }
                    }
                });
            }
            Ok(AcceptResult::Udp(inbound)) => {
                let connector = connector.clone();
                tokio::spawn(async move {
                    match connector.connect_udp().await {
                        Ok(outbound) => {
                            log::info!("relaying udp stream..");
                            relay_udp(inbound, outbound).await;
                        }
                        Err(e) => {
                            log::error!("failed to relay udp stream: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                log::error!("accept failed: {}", e);
            }
        }
    }
}
