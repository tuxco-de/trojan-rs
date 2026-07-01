use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{Buf, Bytes};
use h2::{RecvStream, SendStream};
use http::{Method, Response, StatusCode};
use tokio::{
    io::{
        split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf, ReadHalf,
        WriteHalf,
    },
    sync::{mpsc, Mutex},
    time::{timeout, Duration},
};

use crate::protocol::{
    AcceptResult, Address, ProxyAcceptor, ProxyTcpStream, ProxyUdpStream, UdpRead, UdpWrite,
};

const SING_BOX_MUX_HOST: &str = "sp.mux.sing-box.arpa";
const SING_BOX_MUX_PORT: u16 = 444;
const STREAM_BUFFER_SIZE: usize = 64 * 1024;
const FLAG_UDP: u16 = 1;
const FLAG_PACKET_ADDR: u16 = 2;
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
#[cfg(test)]
const DEFAULT_H2_PREFACE_BYTE_TIMEOUT: Duration = Duration::from_secs(1);

type MuxAcceptResult<T> = AcceptResult<
    SingBoxTcpStream<<T as ProxyAcceptor>::TS>,
    SingBoxUdpStream<<T as ProxyAcceptor>::US>,
>;

pub struct SingBoxMuxAcceptor<T: ProxyAcceptor> {
    inner: T,
    receiver: Arc<Mutex<mpsc::Receiver<MuxAcceptResult<T>>>>,
    sender: mpsc::Sender<MuxAcceptResult<T>>,
    accept_receiver: Arc<Mutex<mpsc::Receiver<io::Result<MuxAcceptResult<T>>>>>,
    accept_sender: mpsc::Sender<io::Result<MuxAcceptResult<T>>>,
    h2_preface_byte_timeout: Duration,
}

impl<T: ProxyAcceptor> SingBoxMuxAcceptor<T> {
    #[cfg(test)]
    pub fn new(inner: T) -> Self {
        Self::new_with_probe_timeout(inner, DEFAULT_H2_PREFACE_BYTE_TIMEOUT)
    }

    pub fn new_with_probe_timeout(inner: T, h2_preface_byte_timeout: Duration) -> Self {
        let (sender, receiver) = mpsc::channel(128);
        let (accept_sender, accept_receiver) = mpsc::channel(1024);
        Self {
            inner,
            receiver: Arc::new(Mutex::new(receiver)),
            sender,
            accept_receiver: Arc::new(Mutex::new(accept_receiver)),
            accept_sender,
            h2_preface_byte_timeout,
        }
    }
}

#[async_trait]
impl<T: ProxyAcceptor + 'static> ProxyAcceptor for SingBoxMuxAcceptor<T> {
    type TS = SingBoxTcpStream<T::TS>;
    type US = SingBoxUdpStream<T::US>;

    async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
        loop {
            tokio::select! {
                result = self.inner.accept() => match result {
                    Ok(AcceptResult::Tcp((stream, address))) if is_sing_box_mux_destination(&address) => {
                        let h2_preface_byte_timeout = self.h2_preface_byte_timeout;
                        let sender = self.sender.clone();
                        let accept_sender = self.accept_sender.clone();
                        tokio::spawn(async move {
                            let result = async {
                                match probe_h2_preface(stream, h2_preface_byte_timeout).await? {
                                    H2ProbeResult::Mux(stream) => {
                                        tokio::spawn(async move {
                                            if let Err(error) = serve_h2mux::<T::TS, _, T::US>(stream, sender).await {
                                                log::debug!("sing-box mux session ended: {}", error);
                                            }
                                        });
                                        Ok(None)
                                    }
                                    H2ProbeResult::Direct(stream) => {
                                        Ok(Some(AcceptResult::Tcp((SingBoxTcpStream::DirectWithPrefix(stream), address))))
                                    }
                                }
                            }.await;
                            match result {
                                Ok(Some(result)) => {
                                    let _ = accept_sender.send(Ok(result)).await;
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    let _ = accept_sender.send(Err(error)).await;
                                }
                            }
                        });
                    }
                    Ok(AcceptResult::Tcp((stream, address))) => {
                        return Ok(AcceptResult::Tcp((SingBoxTcpStream::Direct(stream), address)));
                    }
                    Ok(AcceptResult::Udp(stream)) => return Ok(AcceptResult::Udp(SingBoxUdpStream::Direct(stream))),
                    Err(error) => {
                        log::debug!("sing-box inner accept failed: {}", error);
                        tokio::task::yield_now().await;
                    }
                },
                result = async { self.accept_receiver.lock().await.recv().await } => {
                    return result.ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "sing-box mux probe acceptor closed"))?;
                }
                result = async { self.receiver.lock().await.recv().await } => {
                    return result.ok_or_else(|| io::Error::new(io::ErrorKind::ConnectionAborted, "sing-box mux acceptor closed"));
                }
            }
        }
    }
}

fn is_sing_box_mux_destination(address: &Address) -> bool {
    matches!(address, Address::DomainNameAddress(host, port) if *port == SING_BOX_MUX_PORT && host.eq_ignore_ascii_case(SING_BOX_MUX_HOST))
}

enum H2ProbeResult<S> {
    Mux(PrefixedTcpStream<S>),
    Direct(PrefixedTcpStream<S>),
}

async fn probe_h2_preface<S: ProxyTcpStream>(
    mut stream: S,
    h2_preface_byte_timeout: Duration,
) -> io::Result<H2ProbeResult<S>> {
    let mut prefix = Vec::with_capacity(H2_PREFACE.len());
    for expected in H2_PREFACE {
        let mut byte = [0u8; 1];
        let read = match timeout(h2_preface_byte_timeout, stream.read(&mut byte)).await {
            Ok(read) => read?,
            Err(_) => {
                return Ok(H2ProbeResult::Direct(PrefixedTcpStream::new(
                    prefix, stream,
                )))
            }
        };
        if read == 0 {
            return Ok(H2ProbeResult::Direct(PrefixedTcpStream::new(
                prefix, stream,
            )));
        }
        prefix.push(byte[0]);
        if byte[0] != *expected {
            return Ok(H2ProbeResult::Direct(PrefixedTcpStream::new(
                prefix, stream,
            )));
        }
    }
    Ok(H2ProbeResult::Mux(PrefixedTcpStream::new(prefix, stream)))
}

pub struct PrefixedTcpStream<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> PrefixedTcpStream<S> {
    fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix: Bytes::from(prefix),
            inner,
        }
    }
}

impl<S: ProxyTcpStream> ProxyTcpStream for PrefixedTcpStream<S> {}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedTcpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let length = self.prefix.len().min(buffer.remaining());
            buffer.put_slice(&self.prefix[..length]);
            self.prefix.advance(length);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedTcpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn serve_h2mux<
    B: ProxyTcpStream + 'static,
    S: ProxyTcpStream + 'static,
    U: ProxyUdpStream + 'static,
>(
    stream: S,
    sender: mpsc::Sender<AcceptResult<SingBoxTcpStream<B>, SingBoxUdpStream<U>>>,
) -> io::Result<()> {
    let mut connection = h2::server::handshake(stream).await.map_err(h2_error)?;

    while let Some(request) = connection.accept().await {
        let (request, mut respond) = request.map_err(h2_error)?;
        if request.method() != Method::CONNECT {
            let _ = respond.send_response(
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(())
                    .unwrap(),
                true,
            );
            continue;
        }

        let send = respond
            .send_response(
                Response::builder().status(StatusCode::OK).body(()).unwrap(),
                false,
            )
            .map_err(h2_error)?;
        let (relay, bridge) = tokio::io::duplex(STREAM_BUFFER_SIZE);
        bridge_h2_stream(request.into_body(), send, bridge);

        let sender = sender.clone();
        tokio::spawn(async move {
            if let Err(error) = accept_h2mux_stream::<B, U>(relay, sender).await {
                log::debug!("sing-box mux stream ended: {}", error);
            }
        });
    }
    Ok(())
}

fn bridge_h2_stream(mut receive: RecvStream, send: SendStream<Bytes>, bridge: DuplexStream) {
    let (mut bridge_read, mut bridge_write) = split(bridge);
    tokio::spawn(async move {
        while let Some(chunk) = std::future::poll_fn(|cx| receive.poll_data(cx)).await {
            let chunk = chunk.map_err(h2_error)?;
            let length = chunk.len();
            bridge_write.write_all(&chunk).await?;
            receive
                .flow_control()
                .release_capacity(length)
                .map_err(h2_error)?;
        }
        bridge_write.shutdown().await
    });
    tokio::spawn(async move { write_h2_body(&mut bridge_read, send).await });
}

async fn write_h2_body(
    reader: &mut ReadHalf<DuplexStream>,
    mut send: SendStream<Bytes>,
) -> io::Result<()> {
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let length = reader.read(&mut buffer).await?;
        if length == 0 {
            send.send_data(Bytes::new(), true).map_err(h2_error)?;
            return Ok(());
        }
        let mut data = Bytes::from(buffer[..length].to_vec());
        while !data.is_empty() {
            send.reserve_capacity(data.len());
            let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                .await
                .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "h2 stream closed"))?
                .map_err(h2_error)?;
            let chunk = data.split_to(capacity.min(data.len()));
            send.send_data(chunk, false).map_err(h2_error)?;
        }
    }
}

async fn accept_h2mux_stream<S: ProxyTcpStream + 'static, U: ProxyUdpStream + 'static>(
    mut stream: DuplexStream,
    sender: mpsc::Sender<AcceptResult<SingBoxTcpStream<S>, SingBoxUdpStream<U>>>,
) -> io::Result<()> {
    let flags = stream.read_u16().await?;
    if flags & !(FLAG_UDP | FLAG_PACKET_ADDR) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported sing-box mux flags",
        ));
    }
    let destination = Address::read_from_stream(&mut stream).await?;
    let result = if flags & FLAG_UDP == 0 {
        AcceptResult::Tcp((
            SingBoxTcpStream::Multiplex(SingBoxMuxTcpStream::new(stream)),
            destination,
        ))
    } else {
        AcceptResult::Udp(SingBoxUdpStream::Multiplex(SingBoxMuxUdpStream::new(
            stream,
            destination,
            flags & FLAG_PACKET_ADDR != 0,
        )))
    };
    sender.send(result).await.map_err(|_| {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "sing-box mux acceptor closed",
        )
    })
}

fn h2_error(error: h2::Error) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, error)
}

pub enum SingBoxTcpStream<S> {
    Direct(S),
    DirectWithPrefix(PrefixedTcpStream<S>),
    Multiplex(SingBoxMuxTcpStream),
}

impl<S: ProxyTcpStream> ProxyTcpStream for SingBoxTcpStream<S> {}

impl<S: AsyncRead + Unpin> AsyncRead for SingBoxTcpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::DirectWithPrefix(stream) => Pin::new(stream).poll_read(cx, buffer),
            Self::Multiplex(stream) => Pin::new(stream).poll_read(cx, buffer),
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SingBoxTcpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_write(cx, buffer),
            Self::DirectWithPrefix(stream) => Pin::new(stream).poll_write(cx, buffer),
            Self::Multiplex(stream) => Pin::new(stream).poll_write(cx, buffer),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_flush(cx),
            Self::DirectWithPrefix(stream) => Pin::new(stream).poll_flush(cx),
            Self::Multiplex(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut *self {
            Self::Direct(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::DirectWithPrefix(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Multiplex(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub struct SingBoxMuxTcpStream {
    inner: DuplexStream,
    response_written: bool,
}

impl SingBoxMuxTcpStream {
    fn new(inner: DuplexStream) -> Self {
        Self {
            inner,
            response_written: false,
        }
    }
}

impl AsyncRead for SingBoxMuxTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for SingBoxMuxTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.response_written {
            match Pin::new(&mut self.inner).poll_write(cx, &[0]) {
                Poll::Ready(Ok(1)) => self.response_written = true,
                Poll::Ready(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write sing-box mux response",
                    )))
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.inner).poll_write(cx, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub enum SingBoxUdpStream<U> {
    Direct(U),
    Multiplex(SingBoxMuxUdpStream),
}

pub enum SingBoxUdpRead<R> {
    Direct(R),
    Multiplex(SingBoxMuxUdpRead),
}
pub enum SingBoxUdpWrite<W> {
    Direct(W),
    Multiplex(SingBoxMuxUdpWrite),
}

#[async_trait]
impl<R: UdpRead> UdpRead for SingBoxUdpRead<R> {
    async fn read_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Address)> {
        match self {
            Self::Direct(reader) => reader.read_from(buffer).await,
            Self::Multiplex(reader) => reader.read_from(buffer).await,
        }
    }
}

#[async_trait]
impl<W: UdpWrite> UdpWrite for SingBoxUdpWrite<W> {
    async fn write_to(&mut self, buffer: &[u8], address: &Address) -> io::Result<()> {
        match self {
            Self::Direct(writer) => writer.write_to(buffer, address).await,
            Self::Multiplex(writer) => writer.write_to(buffer, address).await,
        }
    }
}

#[async_trait]
impl<U: ProxyUdpStream> ProxyUdpStream for SingBoxUdpStream<U> {
    type R = SingBoxUdpRead<U::R>;
    type W = SingBoxUdpWrite<U::W>;

    fn split(self) -> (Self::R, Self::W) {
        match self {
            Self::Direct(stream) => {
                let (reader, writer) = stream.split();
                (
                    SingBoxUdpRead::Direct(reader),
                    SingBoxUdpWrite::Direct(writer),
                )
            }
            Self::Multiplex(stream) => {
                let (reader, writer) = stream.split();
                (
                    SingBoxUdpRead::Multiplex(reader),
                    SingBoxUdpWrite::Multiplex(writer),
                )
            }
        }
    }

    fn reunite(reader: Self::R, writer: Self::W) -> Self {
        match (reader, writer) {
            (SingBoxUdpRead::Direct(reader), SingBoxUdpWrite::Direct(writer)) => {
                Self::Direct(U::reunite(reader, writer))
            }
            (SingBoxUdpRead::Multiplex(reader), SingBoxUdpWrite::Multiplex(writer)) => {
                Self::Multiplex(SingBoxMuxUdpStream::reunite(reader, writer))
            }
            _ => unreachable!("mismatched sing-box UDP stream halves"),
        }
    }

    async fn close(mut self) -> io::Result<()> {
        match self {
            Self::Direct(stream) => stream.close().await,
            Self::Multiplex(stream) => stream.close().await,
        }
    }
}

pub struct SingBoxMuxUdpStream {
    reader: SingBoxMuxUdpRead,
    writer: SingBoxMuxUdpWrite,
}
pub struct SingBoxMuxUdpRead {
    inner: ReadHalf<DuplexStream>,
    destination: Address,
    packet_addr: bool,
}
pub struct SingBoxMuxUdpWrite {
    inner: WriteHalf<DuplexStream>,
    packet_addr: bool,
    response_written: bool,
}

impl SingBoxMuxUdpStream {
    fn new(stream: DuplexStream, destination: Address, packet_addr: bool) -> Self {
        let (reader, writer) = split(stream);
        Self {
            reader: SingBoxMuxUdpRead {
                inner: reader,
                destination,
                packet_addr,
            },
            writer: SingBoxMuxUdpWrite {
                inner: writer,
                packet_addr,
                response_written: false,
            },
        }
    }
    fn reunite(reader: SingBoxMuxUdpRead, writer: SingBoxMuxUdpWrite) -> Self {
        Self {
            reader: SingBoxMuxUdpRead {
                inner: reader.inner,
                destination: reader.destination,
                packet_addr: reader.packet_addr,
            },
            writer: SingBoxMuxUdpWrite {
                inner: writer.inner,
                packet_addr: writer.packet_addr,
                response_written: writer.response_written,
            },
        }
    }
    fn split(self) -> (SingBoxMuxUdpRead, SingBoxMuxUdpWrite) {
        (self.reader, self.writer)
    }
    async fn close(mut self) -> io::Result<()> {
        self.writer.inner.shutdown().await
    }
}

#[async_trait]
impl UdpRead for SingBoxMuxUdpRead {
    async fn read_from(&mut self, buffer: &mut [u8]) -> io::Result<(usize, Address)> {
        let address = if self.packet_addr {
            Address::read_from_stream(&mut self.inner).await?
        } else {
            self.destination.clone()
        };
        let length = self.inner.read_u16().await? as usize;
        if length > buffer.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sing-box UDP packet exceeds receive buffer",
            ));
        }
        self.inner.read_exact(&mut buffer[..length]).await?;
        Ok((length, address))
    }
}

#[async_trait]
impl UdpWrite for SingBoxMuxUdpWrite {
    async fn write_to(&mut self, buffer: &[u8], address: &Address) -> io::Result<()> {
        let length = u16::try_from(buffer.len()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "sing-box UDP packet exceeds length limit",
            )
        })?;
        if !self.response_written {
            self.inner.write_all(&[0]).await?;
            self.response_written = true;
        }
        if self.packet_addr {
            write_socks_address(&mut self.inner, address).await?;
        }
        self.inner.write_u16(length).await?;
        self.inner.write_all(buffer).await
    }
}

async fn write_socks_address<W: AsyncWrite + Unpin>(
    writer: &mut W,
    address: &Address,
) -> io::Result<()> {
    match address {
        Address::SocketAddress(std::net::SocketAddr::V4(address)) => {
            writer.write_u8(Address::ADDR_TYPE_IPV4).await?;
            writer.write_all(&address.ip().octets()).await?;
            writer.write_u16(address.port()).await
        }
        Address::SocketAddress(std::net::SocketAddr::V6(address)) => {
            writer.write_u8(Address::ADDR_TYPE_IPV6).await?;
            for segment in address.ip().segments() {
                writer.write_u16(segment).await?;
            }
            writer.write_u16(address.port()).await
        }
        Address::DomainNameAddress(domain, port) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "domain name exceeds length limit",
                )
            })?;
            writer.write_u8(Address::ADDR_TYPE_DOMAIN_NAME).await?;
            writer.write_u8(length).await?;
            writer.write_all(domain.as_bytes()).await?;
            writer.write_u16(*port).await
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use bytes::Bytes;
    use std::{io, sync::Arc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::{mpsc, Mutex};

    use super::{is_sing_box_mux_destination, serve_h2mux, SingBoxMuxAcceptor, SingBoxTcpStream};
    use crate::protocol::{AcceptResult, Address, DummyUdpStream, ProxyAcceptor};

    struct SingleStreamAcceptor {
        stream: Arc<Mutex<Option<DuplexStream>>>,
        address: Address,
    }

    #[async_trait]
    impl ProxyAcceptor for SingleStreamAcceptor {
        type TS = DuplexStream;
        type US = DummyUdpStream;

        async fn accept(&self) -> io::Result<AcceptResult<Self::TS, Self::US>> {
            let stream = self
                .stream
                .lock()
                .await
                .take()
                .ok_or(io::ErrorKind::ConnectionAborted)?;
            Ok(AcceptResult::Tcp((stream, self.address.clone())))
        }
    }

    #[test]
    fn recognizes_the_sing_box_mux_destination() {
        assert!(is_sing_box_mux_destination(&Address::DomainNameAddress(
            "sp.mux.sing-box.arpa".into(),
            444
        )));
        assert!(!is_sing_box_mux_destination(&Address::DomainNameAddress(
            "example.com".into(),
            444
        )));
    }

    #[tokio::test]
    async fn accepts_a_sing_box_h2mux_tcp_stream() {
        let (server_io, client_io) = tokio::io::duplex(64 * 1024);
        let (sender, mut receiver) = mpsc::channel(1);
        let server = tokio::spawn(serve_h2mux::<DuplexStream, _, DummyUdpStream>(
            server_io, sender,
        ));

        let (mut send_request, connection) = h2::client::handshake(client_io).await.unwrap();
        let client = tokio::spawn(connection);
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri("https://localhost")
            .body(())
            .unwrap();
        let (response, mut send) = send_request.send_request(request, false).unwrap();

        let mut header = vec![0, 0, Address::ADDR_TYPE_DOMAIN_NAME, 11];
        header.extend_from_slice(b"example.com");
        header.extend_from_slice(&443u16.to_be_bytes());
        send.send_data(Bytes::from(header), false).unwrap();

        let response = response.await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        let mut stream = match receiver.recv().await.unwrap() {
            crate::protocol::AcceptResult::Tcp((SingBoxTcpStream::Multiplex(stream), address)) => {
                assert_eq!(
                    address,
                    Address::DomainNameAddress("example.com".into(), 443)
                );
                stream
            }
            _ => panic!("expected a multiplexed TCP stream"),
        };
        stream.write_all(b"reply").await.unwrap();

        let mut body = response.into_body();
        let data = std::future::poll_fn(|cx| body.poll_data(cx))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..], b"\0reply");

        client.abort();
        server.abort();
    }

    #[tokio::test]
    async fn does_not_hijack_non_h2_traffic_to_mux_destination() {
        let (server, mut client) = tokio::io::duplex(4096);
        let acceptor = SingBoxMuxAcceptor::new(SingleStreamAcceptor {
            stream: Arc::new(Mutex::new(Some(server))),
            address: Address::DomainNameAddress("sp.mux.sing-box.arpa".into(), 444),
        });
        let client_task = async move {
            client.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
            client
        };

        let (accepted, _) = tokio::join!(acceptor.accept(), client_task);
        let (mut stream, address) = accepted.unwrap().unwrap_tcp_with_addr();
        assert_eq!(
            address,
            Address::DomainNameAddress("sp.mux.sing-box.arpa".into(), 444)
        );
        let mut payload = [0u8; 16];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"GET / HTTP/1.1\r\n");
    }
}
