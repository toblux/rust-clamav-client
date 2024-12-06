use std::{
    net::{SocketAddr, ToSocketAddrs},
    path::Path,
};

use async_net::TcpStream;
use futures_lite::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, Stream, StreamExt};

#[cfg(unix)]
use async_net::unix::UnixStream;

use crate::{Socket, Tcp};

use super::{IoResult, DEFAULT_CHUNK_SIZE, END_OF_STREAM, INSTREAM};

/// The communication protocol to use
pub trait TransportProtocol {
    /// Bidirectional stream
    type Stream: AsyncRead + AsyncWrite + Unpin;

    /// Converts the protocol instance into the corresponding stream
    fn connect(&self) -> impl std::future::Future<Output = std::io::Result<Self::Stream>> + Send;
}

impl<A> TransportProtocol for Tcp<A>
where
    A: ToSocketAddrs + Send + Sync + Clone + 'static,
    <A as ToSocketAddrs>::Iter: Send,
{
    type Stream = TcpStream;

    fn connect(&self) -> impl std::future::Future<Output = std::io::Result<Self::Stream>> + Send {
        async {
            let addrs = self.host_address.clone();
            // It is not possible to set a `Send` trait bound on the iterator of async_net::AsyncToSocketAddrs::to_socket_addrs()
            // However `ToSocketAddress::to_socket_addrs` might block
            // Until we can set the trait bound on `AsyncToSocketAddrs` we have to use `blocking`
            // to inform the async runtime that the task might block
            match blocking::unblock(move || addrs.to_socket_addrs()).await {
                Ok(it) => {
                    let addr: Vec<SocketAddr> = it.collect();
                    TcpStream::connect(addr.as_slice()).await
                }
                Err(err) => Err(err),
            }
        }
    }
}

#[cfg(unix)]
impl<P: AsRef<Path> + Send + Sync> TransportProtocol for Socket<P> {
    type Stream = UnixStream;

    fn connect(&self) -> impl std::future::Future<Output = std::io::Result<Self::Stream>> + Send {
        UnixStream::connect(&self.socket_path)
    }
}

/// Sends a command to ClamAV
pub async fn send_command<RW: AsyncRead + AsyncWrite + Unpin>(
    mut stream: RW,
    command: &[u8],
) -> IoResult {
    stream.write_all(command).await?;
    // stream.flush().await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

/// Scan async readable data with ClamAV
pub async fn scan<R: AsyncRead + Unpin, RW: AsyncRead + AsyncWrite + Unpin>(
    mut input: R,
    chunk_size: Option<usize>,
    mut stream: RW,
) -> IoResult {
    stream.write_all(INSTREAM).await?;

    let chunk_size = chunk_size
        .unwrap_or(DEFAULT_CHUNK_SIZE)
        .min(u32::MAX as usize);

    let mut buffer = vec![0; chunk_size];

    loop {
        let len = input.read(&mut buffer[..]).await?;
        if len != 0 {
            stream.write_all(&(len as u32).to_be_bytes()).await?;
            stream.write_all(&buffer[..len]).await?;
        } else {
            stream.write_all(END_OF_STREAM).await?;
            stream.flush().await?;
            break;
        }
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

/// Scans a stream of data with ClamAV
pub async fn scan_stream<S, RW>(
    input_stream: S,
    chunk_size: Option<usize>,
    mut output_stream: RW,
) -> IoResult
where
    S: Stream<Item = Result<bytes::Bytes, std::io::Error>>,
    RW: AsyncRead + AsyncWrite + Unpin,
{
    output_stream.write_all(INSTREAM).await?;

    let chunk_size = chunk_size
        .unwrap_or(DEFAULT_CHUNK_SIZE)
        .min(u32::MAX as usize);

    let mut input_stream = std::pin::pin!(input_stream);

    while let Some(bytes) = input_stream.next().await {
        let bytes = bytes?;
        let bytes = bytes.as_ref();
        for chunk in bytes.chunks(chunk_size) {
            let len = chunk.len();
            output_stream.write_all(&(len as u32).to_be_bytes()).await?;
            output_stream.write_all(chunk).await?;
        }
    }

    output_stream.write_all(END_OF_STREAM).await?;
    output_stream.flush().await?;

    let mut response = Vec::new();
    output_stream.read_to_end(&mut response).await?;
    Ok(response)
}
