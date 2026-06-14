use async_trait::async_trait;
use std::io;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::Error;

pub mod direct;
pub mod fallback;
pub mod mux;
pub mod socks5;
pub mod tls;
pub mod trojan;
pub mod vless;
pub mod websocket;

pub fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("protocol: {}", message.to_string())).into()
}

pub trait ProxyTcpStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}
pub mod address;

pub use self::address::Address;

#[async_trait]
pub trait UdpRead: Send + Sync + Unpin {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)>;
}
#[async_trait]
pub trait UdpWrite: Send + Sync + Unpin {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> io::Result<()>;
}

#[async_trait]
pub trait ProxyUdpStream: Send + Unpin {
    type R: UdpRead;
    type W: UdpWrite;
    fn split(self) -> (Self::R, Self::W);
    fn reunite(r: Self::R, w: Self::W) -> Self;
    async fn close(self) -> io::Result<()>;
}

#[async_trait]
pub trait ProxyConnector: Send + Sync {
    type TS: ProxyTcpStream + 'static;
    type US: ProxyUdpStream + 'static;
    async fn connect_tcp(&self, addr: &Address) -> io::Result<Self::TS>;
    async fn connect_udp(&self) -> io::Result<Self::US>;
}

pub enum AcceptResult<T: ProxyTcpStream, U: ProxyUdpStream> {
    Tcp((T, Address)),
    Udp(U),
}

impl<T: ProxyTcpStream, U: ProxyUdpStream> AcceptResult<T, U> {
    pub fn unwrap_tcp_with_addr(self) -> (T, Address) {
        match self {
            Self::Tcp(t) => t,
            _ => unreachable!(),
        }
    }
}

#[async_trait]
pub trait ProxyAcceptor: Send + Sync {
    type TS: ProxyTcpStream + 'static;
    type US: ProxyUdpStream + 'static;
    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>>;
}

pub struct DummyUdpRead {}

#[async_trait]
impl UdpRead for DummyUdpRead {
    async fn read_from(&mut self, _: &mut [u8]) -> io::Result<(usize, Address)> {
        unimplemented!()
    }
}

pub struct DummyUdpWrite {}

#[async_trait]
impl UdpWrite for DummyUdpWrite {
    async fn write_to(&mut self, _: &[u8], _: &Address) -> io::Result<()> {
        unimplemented!()
    }
}

pub struct DummyUdpStream {}

#[async_trait]
impl UdpRead for DummyUdpStream {
    async fn read_from(&mut self, _: &mut [u8]) -> io::Result<(usize, Address)> {
        unimplemented!()
    }
}

#[async_trait]
impl UdpWrite for DummyUdpStream {
    async fn write_to(&mut self, _: &[u8], _: &Address) -> io::Result<()> {
        unimplemented!()
    }
}

#[async_trait]
impl ProxyUdpStream for DummyUdpStream {
    type R = DummyUdpRead;
    type W = DummyUdpWrite;
    fn split(self) -> (Self::R, Self::W) {
        unimplemented!()
    }
    fn reunite(_: Self::R, _: Self::W) -> Self {
        unimplemented!()
    }
    async fn close(self) -> io::Result<()> {
        unimplemented!()
    }
}
