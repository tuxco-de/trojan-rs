use super::new_error;
use crate::protocol::{AcceptResult, Address, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite};
use async_trait::async_trait;
use bytes::{Buf, Bytes};
use futures_core::ready;
use futures_util::FutureExt;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
};
use tokio::{
    io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::mpsc::{channel, error::TrySendError, Receiver, Sender},
};

const STATUS_NEW: u8 = 0x01;
const STATUS_KEEP: u8 = 0x02;
const STATUS_END: u8 = 0x03;
const STATUS_KEEP_ALIVE: u8 = 0x04;

const OPTION_DATA: u8 = 0x01;
const NETWORK_TCP: u8 = 0x01;
const NETWORK_UDP: u8 = 0x02;
const MAX_METADATA_LEN: usize = 512;
const MAX_DATA_LEN: usize = 0xffff;
const SHARED_CHANNEL_LEN: usize = 0x200;
const PRIVATE_CHANNEL_LEN: usize = 0x50;

type MuxAcceptResult<S> =
    AcceptResult<super::VlessTcpStream<S>, super::VlessUdpStream<super::VlessTcpStream<S>>>;
type WriteFuture = Pin<
    Box<
        dyn futures_core::Future<
                Output = Result<(), tokio::sync::mpsc::error::SendError<MuxCoolFrame>>,
            > + Send
            + Sync,
    >,
>;

struct MuxCoolFrame {
    session_id: u16,
    status: u8,
    packet_address: Option<Address>,
    data: Option<Bytes>,
}

impl MuxCoolFrame {
    async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> io::Result<()> {
        let option = if self.data.is_some() { OPTION_DATA } else { 0 };
        let metadata_len = 4 + self.packet_address.as_ref().map_or(0, mux_udp_address_len);
        writer.write_u16(metadata_len as u16).await?;
        writer.write_u16(self.session_id).await?;
        writer.write_u8(self.status).await?;
        writer.write_u8(option).await?;
        if let Some(address) = self.packet_address.as_ref() {
            write_mux_udp_address(writer, address).await?;
        }
        if let Some(data) = &self.data {
            let length = u16::try_from(data.len())
                .map_err(|_| new_error("Mux.Cool data exceeds length limit"))?;
            writer.write_u16(length).await?;
            writer.write_all(data).await?;
        }
        writer.flush().await
    }
}

fn mux_udp_address_len(address: &Address) -> usize {
    match address {
        Address::SocketAddress(SocketAddr::V4(_)) => 1 + 2 + 1 + 4,
        Address::SocketAddress(SocketAddr::V6(_)) => 1 + 2 + 1 + 16,
        Address::DomainNameAddress(domain, _) => 1 + 2 + 1 + 1 + domain.len(),
    }
}

async fn write_mux_udp_address<W: AsyncWrite + Unpin>(
    writer: &mut W,
    address: &Address,
) -> io::Result<()> {
    writer.write_u8(NETWORK_UDP).await?;
    match address {
        Address::SocketAddress(SocketAddr::V4(address)) => {
            writer.write_u16(address.port()).await?;
            writer.write_u8(0x01).await?;
            writer.write_all(&address.ip().octets()).await
        }
        Address::DomainNameAddress(domain, port) => {
            let length = u8::try_from(domain.len())
                .map_err(|_| new_error("Mux.Cool domain exceeds length limit"))?;
            writer.write_u16(*port).await?;
            writer.write_u8(0x02).await?;
            writer.write_u8(length).await?;
            writer.write_all(domain.as_bytes()).await
        }
        Address::SocketAddress(SocketAddr::V6(address)) => {
            writer.write_u16(address.port()).await?;
            writer.write_u8(0x03).await?;
            writer.write_all(&address.ip().octets()).await
        }
    }
}

struct MuxCoolMetadata {
    session_id: u16,
    status: u8,
    network: Option<u8>,
    address: Option<Address>,
}

impl MuxCoolMetadata {
    async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<(Self, Option<Bytes>)> {
        let metadata_len = reader.read_u16().await? as usize;
        if !(4..=MAX_METADATA_LEN).contains(&metadata_len) {
            return Err(new_error(format!(
                "invalid Mux.Cool metadata length {}",
                metadata_len
            )));
        }

        let mut metadata = vec![0u8; metadata_len];
        reader.read_exact(&mut metadata).await?;
        let mut cursor = &metadata[..];
        let session_id = cursor.get_u16();
        let status = cursor.get_u8();
        let option = cursor.get_u8();
        let mut network = None;
        let mut address = None;

        if status == STATUS_NEW
            || (status == STATUS_KEEP && cursor.remaining() > 0 && cursor[0] == NETWORK_UDP)
        {
            if cursor.remaining() < 4 {
                return Err(new_error("insufficient Mux.Cool target metadata"));
            }
            let target_network = cursor.get_u8();
            let target = read_mux_address(&mut cursor)?;
            network = Some(target_network);
            address = Some(target);
        }

        let data = if option & OPTION_DATA != 0 {
            let data_len = reader.read_u16().await? as usize;
            let mut data = vec![0u8; data_len];
            reader.read_exact(&mut data).await?;
            Some(Bytes::from(data))
        } else {
            None
        };

        Ok((
            Self {
                session_id,
                status,
                network,
                address,
            },
            data,
        ))
    }
}

fn read_mux_address(cursor: &mut &[u8]) -> io::Result<Address> {
    let port = cursor.get_u16();
    let address_type = cursor.get_u8();
    match address_type {
        0x01 => {
            if cursor.remaining() < 4 {
                return Err(new_error("short Mux.Cool IPv4 address"));
            }
            let mut address = [0u8; 4];
            cursor.copy_to_slice(&mut address);
            Ok(Address::SocketAddress(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(address)),
                port,
            )))
        }
        0x02 => {
            if !cursor.has_remaining() {
                return Err(new_error("short Mux.Cool domain address"));
            }
            let length = cursor.get_u8() as usize;
            if cursor.remaining() < length {
                return Err(new_error("short Mux.Cool domain address"));
            }
            let domain = String::from_utf8(cursor[..length].to_vec())
                .map_err(|_| new_error("invalid Mux.Cool domain address"))?;
            cursor.advance(length);
            Ok(Address::DomainNameAddress(domain, port))
        }
        0x03 => {
            if cursor.remaining() < 16 {
                return Err(new_error("short Mux.Cool IPv6 address"));
            }
            let mut address = [0u8; 16];
            cursor.copy_to_slice(&mut address);
            Ok(Address::SocketAddress(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(address)),
                port,
            )))
        }
        _ => Err(new_error(format!(
            "unsupported Mux.Cool address type {}",
            address_type
        ))),
    }
}

enum MuxCoolSessionHandle {
    Tcp {
        tx: Sender<Bytes>,
        closed: Arc<AtomicBool>,
    },
    Udp {
        tx: Sender<MuxCoolUdpPacket>,
        closed: Arc<AtomicBool>,
        default_address: Address,
    },
}

impl MuxCoolSessionHandle {
    fn close(self) {
        match self {
            Self::Tcp { closed, .. } | Self::Udp { closed, .. } => {
                closed.store(true, Ordering::Relaxed);
            }
        }
    }
}

pub struct MuxCoolStream {
    session_id: u16,
    tx: Sender<MuxCoolFrame>,
    rx: Receiver<Bytes>,
    read_buffer: Option<Bytes>,
    write_buffer: Option<Bytes>,
    write_future: Option<WriteFuture>,
    closed: Arc<AtomicBool>,
}

impl MuxCoolStream {
    fn new(
        session_id: u16,
        tx: Sender<MuxCoolFrame>,
        rx: Receiver<Bytes>,
    ) -> (Self, Arc<AtomicBool>) {
        let closed = Arc::new(AtomicBool::new(false));
        (
            Self {
                session_id,
                tx,
                rx,
                read_buffer: None,
                write_buffer: None,
                write_future: None,
                closed: Arc::clone(&closed),
            },
            closed,
        )
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn try_send_frame(&mut self, frame: MuxCoolFrame) -> io::Result<bool> {
        if self.is_closed() {
            return Err(io::ErrorKind::ConnectionReset.into());
        }
        match self.tx.try_send(frame) {
            Ok(()) => Ok(true),
            Err(TrySendError::Full(frame)) => {
                let tx = self.tx.clone();
                self.write_future = Some(Box::pin(async move {
                    tx.send(frame).await?;
                    Ok(())
                }));
                Ok(false)
            }
            Err(TrySendError::Closed(_)) => Err(io::ErrorKind::ConnectionReset.into()),
        }
    }

    fn queue_end(&self) {
        let _ = self.tx.try_send(MuxCoolFrame {
            session_id: self.session_id,
            status: STATUS_END,
            packet_address: None,
            data: None,
        });
    }
}

impl AsyncRead for MuxCoolStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(read_buffer) = &mut self.read_buffer {
                if read_buffer.len() <= buf.remaining() {
                    buf.put_slice(read_buffer);
                    self.read_buffer = None;
                } else {
                    let length = buf.remaining();
                    buf.put_slice(&read_buffer[..length]);
                    read_buffer.advance(length);
                }
                return Poll::Ready(Ok(()));
            }
            match ready!(self.rx.poll_recv(cx)) {
                Some(data) => self.read_buffer = Some(data),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for MuxCoolStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            if let Some(future) = &mut self.write_future {
                ready!(future.poll_unpin(cx)).map_err(|_| io::ErrorKind::ConnectionReset)?;
                self.write_future = None;
            }
            if self.write_buffer.is_none() {
                let length = buf.len().min(MAX_DATA_LEN);
                self.write_buffer = Some(Bytes::copy_from_slice(&buf[..length]));
            }
            let data = self.write_buffer.take().unwrap();
            let length = data.len();
            let frame = MuxCoolFrame {
                session_id: self.session_id,
                status: STATUS_KEEP,
                packet_address: None,
                data: Some(data),
            };
            if self.try_send_frame(frame)? {
                return Poll::Ready(Ok(length));
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(future) = &mut self.write_future {
            ready!(future.poll_unpin(cx)).map_err(|_| io::ErrorKind::ConnectionReset)?;
            self.write_future = None;
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        if !self.closed.swap(true, Ordering::Relaxed) {
            self.queue_end();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for MuxCoolStream {
    fn drop(&mut self) {
        if !self.closed.swap(true, Ordering::Relaxed) {
            self.queue_end();
        }
    }
}

struct MuxCoolUdpPacket {
    data: Bytes,
    address: Address,
}

pub struct MuxCoolUdpStream {
    reader: MuxCoolUdpRead,
    writer: MuxCoolUdpWrite,
}

pub struct MuxCoolUdpRead {
    rx: Receiver<MuxCoolUdpPacket>,
}

pub struct MuxCoolUdpWrite {
    session_id: u16,
    tx: Sender<MuxCoolFrame>,
    closed: Arc<AtomicBool>,
}

impl MuxCoolUdpStream {
    fn new(
        session_id: u16,
        tx: Sender<MuxCoolFrame>,
        rx: Receiver<MuxCoolUdpPacket>,
    ) -> (Self, Arc<AtomicBool>) {
        let closed = Arc::new(AtomicBool::new(false));
        (
            Self {
                reader: MuxCoolUdpRead { rx },
                writer: MuxCoolUdpWrite {
                    session_id,
                    tx,
                    closed: Arc::clone(&closed),
                },
            },
            closed,
        )
    }

    pub fn split(self) -> (MuxCoolUdpRead, MuxCoolUdpWrite) {
        (self.reader, self.writer)
    }

    pub fn reunite(reader: MuxCoolUdpRead, writer: MuxCoolUdpWrite) -> Self {
        Self { reader, writer }
    }

    pub async fn close(mut self) -> io::Result<()> {
        self.writer.close().await
    }
}

#[async_trait]
impl UdpRead for MuxCoolUdpRead {
    async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let packet =
            self.rx.recv().await.ok_or_else(|| {
                io::Error::new(io::ErrorKind::ConnectionReset, "Mux.Cool UDP closed")
            })?;
        if packet.data.len() > buf.len() {
            return Err(new_error(format!(
                "Mux.Cool UDP packet of {} bytes exceeds receive buffer",
                packet.data.len()
            )));
        }
        buf[..packet.data.len()].copy_from_slice(&packet.data);
        Ok((packet.data.len(), packet.address))
    }
}

impl MuxCoolUdpWrite {
    async fn close(&mut self) -> io::Result<()> {
        if !self.closed.swap(true, Ordering::Relaxed) {
            let _ = self
                .tx
                .send(MuxCoolFrame {
                    session_id: self.session_id,
                    status: STATUS_END,
                    packet_address: None,
                    data: None,
                })
                .await;
        }
        Ok(())
    }
}

#[async_trait]
impl UdpWrite for MuxCoolUdpWrite {
    async fn write_to(&mut self, buf: &[u8], addr: &Address) -> io::Result<()> {
        let length = u16::try_from(buf.len())
            .map_err(|_| new_error("Mux.Cool UDP packet exceeds length limit"))?;
        let data = Bytes::copy_from_slice(&buf[..length as usize]);
        self.tx
            .send(MuxCoolFrame {
                session_id: self.session_id,
                status: STATUS_KEEP,
                packet_address: Some(addr.clone()),
                data: Some(data),
            })
            .await
            .map_err(|_| io::ErrorKind::ConnectionReset.into())
    }
}

#[async_trait]
impl ProxyUdpStream for MuxCoolUdpStream {
    type R = MuxCoolUdpRead;
    type W = MuxCoolUdpWrite;

    fn split(self) -> (Self::R, Self::W) {
        self.split()
    }

    fn reunite(r: Self::R, w: Self::W) -> Self {
        Self::reunite(r, w)
    }

    async fn close(self) -> io::Result<()> {
        self.close().await
    }
}

pub async fn serve_mux_cool<S: ProxyTcpStream + 'static>(
    stream: S,
    accept_tx: Sender<MuxAcceptResult<S>>,
) -> io::Result<()> {
    let (mut reader, mut writer) = split(stream);
    let (write_tx, mut write_rx) = channel::<MuxCoolFrame>(SHARED_CHANNEL_LEN);
    let mut sessions: HashMap<u16, MuxCoolSessionHandle> = HashMap::new();

    let write_handle = tokio::spawn(async move {
        while let Some(frame) = write_rx.recv().await {
            frame.write_to(&mut writer).await?;
        }
        io::Result::Ok(())
    });

    let result = async {
        loop {
            let (metadata, data) = MuxCoolMetadata::read_from(&mut reader).await?;
            match metadata.status {
                STATUS_NEW => {
                    let Some(address) = metadata.address else {
                        return Err(new_error("Mux.Cool new stream missing target"));
                    };
                    match metadata.network {
                        Some(NETWORK_TCP) => {
                            let (tx, rx) = channel(PRIVATE_CHANNEL_LEN);
                            if let Some(data) = data {
                                tx.send(data)
                                    .await
                                    .map_err(|_| io::ErrorKind::ConnectionReset)?;
                            }
                            let (stream, closed) =
                                MuxCoolStream::new(metadata.session_id, write_tx.clone(), rx);
                            sessions.insert(
                                metadata.session_id,
                                MuxCoolSessionHandle::Tcp { tx, closed },
                            );
                            accept_tx
                                .send(AcceptResult::Tcp((
                                    super::VlessTcpStream::MuxCool(stream),
                                    address,
                                )))
                                .await
                                .map_err(|_| io::ErrorKind::ConnectionAborted)?;
                        }
                        Some(NETWORK_UDP) => {
                            let (tx, rx) = channel(PRIVATE_CHANNEL_LEN);
                            if let Some(data) = data {
                                tx.send(MuxCoolUdpPacket {
                                    data,
                                    address: address.clone(),
                                })
                                .await
                                .map_err(|_| io::ErrorKind::ConnectionReset)?;
                            }
                            let (stream, closed) =
                                MuxCoolUdpStream::new(metadata.session_id, write_tx.clone(), rx);
                            sessions.insert(
                                metadata.session_id,
                                MuxCoolSessionHandle::Udp {
                                    tx,
                                    closed,
                                    default_address: address.clone(),
                                },
                            );
                            accept_tx
                                .send(AcceptResult::Udp(super::VlessUdpStream::mux_cool(stream)))
                                .await
                                .map_err(|_| io::ErrorKind::ConnectionAborted)?;
                        }
                        _ => return Err(new_error("unsupported Mux.Cool network")),
                    }
                }
                STATUS_KEEP => {
                    if let Some(data) = data {
                        if let Some(handle) = sessions.get(&metadata.session_id) {
                            let send_result = match handle {
                                MuxCoolSessionHandle::Tcp { tx, .. } => {
                                    tx.send(data).await.map_err(|_| ())
                                }
                                MuxCoolSessionHandle::Udp {
                                    tx,
                                    default_address,
                                    ..
                                } => {
                                    let address = metadata
                                        .address
                                        .clone()
                                        .unwrap_or_else(|| default_address.clone());
                                    tx.send(MuxCoolUdpPacket { data, address })
                                        .await
                                        .map_err(|_| ())
                                }
                            };
                            if send_result.is_err() {
                                sessions
                                    .remove(&metadata.session_id)
                                    .map(MuxCoolSessionHandle::close);
                            }
                        } else {
                            write_tx
                                .send(MuxCoolFrame {
                                    session_id: metadata.session_id,
                                    status: STATUS_END,
                                    packet_address: None,
                                    data: None,
                                })
                                .await
                                .map_err(|_| io::ErrorKind::ConnectionReset)?;
                        }
                    }
                }
                STATUS_END => {
                    sessions
                        .remove(&metadata.session_id)
                        .map(MuxCoolSessionHandle::close);
                }
                STATUS_KEEP_ALIVE => {}
                status => return Err(new_error(format!("unknown Mux.Cool status {}", status))),
            }
        }
    }
    .await;

    for (_, handle) in sessions {
        handle.close();
    }
    drop(write_tx);
    write_handle.abort();
    result
}
