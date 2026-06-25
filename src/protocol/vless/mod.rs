pub mod acceptor;

use crate::{
    error::Error,
    protocol::{Address, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite},
};
use async_trait::async_trait;
use std::io;
use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};

const VERSION: u8 = 0;
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;
const COMMAND_MUX: u8 = 0x03;

fn new_error<T: ToString>(message: T) -> io::Error {
    Error::new(format!("vless: {}", message.to_string())).into()
}

enum RequestHeader {
    Tcp(Address),
    Udp(Address),
}

impl RequestHeader {
    async fn read_from<R>(stream: &mut R, valid_users: &[[u8; 16]]) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let mut prefix = [0u8; 18];
        stream.read_exact(&mut prefix).await?;
        if prefix[0] != VERSION {
            return Err(new_error(format!("unsupported version {}", prefix[0])));
        }
        if !contains_user(valid_users, &prefix[1..17]) {
            return Err(new_error("invalid user id"));
        }

        let addons_len = prefix[17] as usize;
        if addons_len != 0 {
            let mut addons = vec![0u8; addons_len];
            stream.read_exact(&mut addons).await?;
            log::debug!(
                "ignoring unsupported VLESS request addons of {} bytes",
                addons_len
            );
        }

        let command = stream.read_u8().await?;
        if command == COMMAND_MUX {
            return Err(new_error("VLESS mux is not supported"));
        }
        if command != COMMAND_TCP && command != COMMAND_UDP {
            return Err(new_error(format!("unsupported command {}", command)));
        }

        let address = read_address(stream).await?;
        match command {
            COMMAND_TCP => Ok(Self::Tcp(address)),
            COMMAND_UDP => Ok(Self::Udp(address)),
            _ => unreachable!(),
        }
    }
}

fn contains_user(valid_users: &[[u8; 16]], candidate: &[u8]) -> bool {
    let mut any_match = 0u8;
    for user in valid_users {
        let mut difference = 0u8;
        for (expected, actual) in user.iter().zip(candidate.iter()) {
            difference |= expected ^ actual;
        }
        any_match |= (difference == 0) as u8;
    }
    any_match != 0
}

async fn read_address<R>(stream: &mut R) -> io::Result<Address>
where
    R: AsyncRead + Unpin,
{
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    let port = stream.read_u16().await?;
    let address_type = stream.read_u8().await?;
    match address_type {
        0x01 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            Ok(Address::SocketAddress(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(address)),
                port,
            )))
        }
        0x02 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err(new_error("empty domain name"));
            }
            let mut domain = vec![0u8; length];
            stream.read_exact(&mut domain).await?;
            let domain = String::from_utf8(domain).map_err(|_| new_error("invalid domain name"))?;
            if !is_compatible_domain_name(&domain) {
                return Err(new_error("invalid domain name"));
            }
            Ok(Address::DomainNameAddress(domain, port))
        }
        0x03 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
            Ok(Address::SocketAddress(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(address)),
                port,
            )))
        }
        _ => Err(new_error(format!(
            "unsupported address type {}",
            address_type
        ))),
    }
}

fn is_compatible_domain_name(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    for label in domain.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        let bytes = label.as_bytes();
        if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
            return false;
        }
        if !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-' || *byte == b'_')
        {
            return false;
        }
    }
    true
}

pub struct VlessUdpReader<T> {
    inner: T,
    address: Address,
}

#[async_trait]
impl<T: AsyncRead + Unpin + Send + Sync> UdpRead for VlessUdpReader<T> {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let payload_len = self.inner.read_u16().await? as usize;
        if payload_len > buf.len() {
            return Err(new_error(format!(
                "UDP packet of {} bytes exceeds receive buffer",
                payload_len
            )));
        }
        self.inner.read_exact(&mut buf[..payload_len]).await?;
        Ok((payload_len, self.address.clone()))
    }
}

pub struct VlessUdpWriter<T> {
    inner: T,
}

#[async_trait]
impl<T: AsyncWrite + Unpin + Send + Sync> UdpWrite for VlessUdpWriter<T> {
    async fn write_to(&mut self, buf: &[u8], _: &Address) -> io::Result<()> {
        let payload_len = u16::try_from(buf.len())
            .map_err(|_| new_error("UDP packet exceeds VLESS length limit"))?;
        self.inner.write_u16(payload_len).await?;
        self.inner.write_all(buf).await?;
        self.inner.flush().await
    }
}

pub struct VlessUdpStream<T: ProxyTcpStream> {
    reader: VlessUdpReader<ReadHalf<T>>,
    writer: VlessUdpWriter<WriteHalf<T>>,
}

impl<T: ProxyTcpStream> VlessUdpStream<T> {
    pub(super) fn new(inner: T, address: Address) -> Self {
        let (reader, writer) = split(inner);
        Self {
            reader: VlessUdpReader {
                inner: reader,
                address,
            },
            writer: VlessUdpWriter { inner: writer },
        }
    }
}

#[async_trait]
impl<T: ProxyTcpStream> ProxyUdpStream for VlessUdpStream<T> {
    type R = VlessUdpReader<ReadHalf<T>>;
    type W = VlessUdpWriter<WriteHalf<T>>;

    fn split(self) -> (Self::R, Self::W) {
        (self.reader, self.writer)
    }

    fn reunite(reader: Self::R, writer: Self::W) -> Self {
        Self { reader, writer }
    }

    async fn close(self) -> io::Result<()> {
        let mut inner = self.reader.inner.unsplit(self.writer.inner);
        inner.shutdown().await
    }
}

#[cfg(test)]
mod tests {
    use super::{contains_user, is_compatible_domain_name, read_address, RequestHeader};
    use crate::protocol::Address;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use uuid::Uuid;

    #[tokio::test]
    async fn decodes_standard_tcp_request() {
        let user = Uuid::parse_str("d342d11e-d424-4583-b36e-524ab1f0afa4").unwrap();
        let mut request = vec![0];
        request.extend_from_slice(user.as_bytes());
        request.extend_from_slice(&[0, 1, 0x01, 0xbb, 2, 11]);
        request.extend_from_slice(b"example.com");

        let mut input = request.as_slice();
        let header = RequestHeader::read_from(&mut input, &[*user.as_bytes()])
            .await
            .unwrap();
        match header {
            RequestHeader::Tcp(Address::DomainNameAddress(domain, port)) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("unexpected VLESS request"),
        }
    }

    #[tokio::test]
    async fn tolerates_unknown_request_addons() {
        let user = Uuid::parse_str("d342d11e-d424-4583-b36e-524ab1f0afa4").unwrap();
        let mut request = vec![0];
        request.extend_from_slice(user.as_bytes());
        request.extend_from_slice(&[3, 0xaa, 0xbb, 0xcc, 1, 0x01, 0xbb, 2, 11]);
        request.extend_from_slice(b"example.com");

        let mut input = request.as_slice();
        let header = RequestHeader::read_from(&mut input, &[*user.as_bytes()])
            .await
            .unwrap();
        match header {
            RequestHeader::Tcp(Address::DomainNameAddress(domain, port)) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("unexpected VLESS request"),
        }
    }

    #[tokio::test]
    async fn decodes_vless_port_before_ipv4_address() {
        let mut input = [0x00, 0x35, 1, 8, 8, 8, 8].as_slice();
        let address = read_address(&mut input).await.unwrap();
        assert_eq!(
            address,
            Address::SocketAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53))
        );
    }

    #[test]
    fn user_matching_checks_all_configured_ids() {
        let first = *Uuid::nil().as_bytes();
        let second = *Uuid::max().as_bytes();
        assert!(contains_user(&[first, second], &second));
        assert!(!contains_user(&[first], &second));
    }

    #[test]
    fn validates_domain_name_boundaries() {
        assert!(is_compatible_domain_name("dns.example"));
        assert!(is_compatible_domain_name("_service.example"));
        assert!(!is_compatible_domain_name("-bad.example"));
        assert!(!is_compatible_domain_name("bad-.example"));
        assert!(!is_compatible_domain_name("bad..example"));
        assert!(!is_compatible_domain_name("bad/example"));
    }
}
