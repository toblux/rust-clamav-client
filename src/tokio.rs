use async_trait::async_trait;
use std::path::Path;
use tokio::{
    fs::File,
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs},
};

#[cfg(unix)]
use tokio::net::UnixStream;

#[cfg(feature = "tokio-stream")]
use tokio_stream::{Stream, StreamExt};

use super::{IoResult, DEFAULT_CHUNK_SIZE, END_OF_STREAM, INSTREAM, PING, PONG};

async fn _ping<RW: AsyncRead + AsyncWrite + Unpin>(mut stream: RW) -> IoResult {
    stream.write_all(PING).await?;
    stream.flush().await?;

    let capacity = PONG.len();
    let mut response = Vec::with_capacity(capacity);
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

async fn scan<R: AsyncRead + Unpin, RW: AsyncRead + AsyncWrite + Unpin>(
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

#[cfg(feature = "tokio-stream")]
async fn _scan_stream<
    S: Stream<Item = Result<bytes::Bytes, std::io::Error>>,
    RW: AsyncRead + AsyncWrite + Unpin,
>(
    input_stream: S,
    chunk_size: Option<usize>,
    mut output_stream: RW,
) -> IoResult {
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

/// Sends a ping request to ClamAV using a Unix socket connection
///
/// This function establishes a Unix socket connection to a ClamAV server at the
/// specified `socket_path` and sends a ping request to it.
///
/// # Arguments
///
/// * `transport_protocol`: The protocol to use (either TCP or a Unix socket connection)
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let clamd_available = match clamav_client::tokio::ping_socket("/tmp/clamd.socket").await {
///     Ok(ping_response) => ping_response == clamav_client::PONG,
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// # }
/// ```
///
#[cfg(unix)]
pub async fn ping_socket<P: AsRef<Path>>(socket_path: P) -> IoResult {
    ping(Socket(socket_path)).await
}

/// Scans a file for viruses using a Unix socket connection
///
/// This function reads data from a file located at the specified `file_path`
/// and streams it to a ClamAV server through a Unix socket connection for
/// scanning.
///
/// # Arguments
///
/// * `file_path`: The path to the file to be scanned
/// * `socket_path`: The path to the Unix socket of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
#[cfg(unix)]
pub async fn scan_file_socket<P: AsRef<Path>>(
    file_path: P,
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_file(file_path, Socket(socket_path), chunk_size).await
}

/// Scans a data buffer for viruses using a Unix socket connection
///
/// This function streams the provided `buffer` data to a ClamAV server through
/// a Unix socket connection for scanning.
///
/// # Arguments
///
/// * `buffer`: The data to be scanned
/// * `socket_path`: The path to the Unix socket of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
#[cfg(unix)]
pub async fn scan_buffer_socket<P: AsRef<Path>>(
    buffer: &[u8],
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_buffer(buffer, Socket(socket_path), chunk_size).await
}

/// Scans a stream for viruses using a Unix socket connection
///
/// This function sends the provided stream to a ClamAV server through a Unix
/// socket connection for scanning.
///
/// # Arguments
///
/// * `input_stream`: The stream to be scanned
/// * `socket_path`: The path to the Unix socket of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
#[cfg(all(unix, feature = "tokio-stream"))]
pub async fn scan_stream_socket<
    S: Stream<Item = Result<bytes::Bytes, io::Error>>,
    P: AsRef<Path>,
>(
    input_stream: S,
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_stream(input_stream, Socket(socket_path), chunk_size).await
}

/// Sends a ping request to ClamAV using a TCP connection
///
/// This function establishes a TCP connection to a ClamAV server at the
/// specified `host_address` and sends a ping request to it.
///
/// # Example
///
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let clamd_available = match clamav_client::tokio::ping_tcp("localhost:3310").await {
///     Ok(ping_response) => ping_response == clamav_client::PONG,
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// # }
/// ```
///
pub async fn ping_tcp<A: ToSocketAddrs>(host_address: A) -> IoResult {
    ping(Tcp(host_address)).await
}

/// Scans a file for viruses using a TCP connection
///
/// This function reads data from a file located at the specified `file_path`
/// and streams it to a ClamAV server through a TCP connection for scanning.
///
/// # Arguments
///
/// * `file_path`: The path to the file to be scanned
/// * `host_address`: The address (host and port) of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
pub async fn scan_file_tcp<P: AsRef<Path>, A: ToSocketAddrs>(
    file_path: P,
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_file(file_path, Tcp(host_address), chunk_size).await
}

/// Scans a data buffer for viruses using a TCP connection
///
/// This function streams the provided `buffer` data to a ClamAV server through
/// a TCP connection for scanning.
///
/// # Arguments
///
/// * `buffer`: The data to be scanned
/// * `host_address`: The address (host and port) of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
pub async fn scan_buffer_tcp<A: ToSocketAddrs>(
    buffer: &[u8],
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_buffer(buffer, Tcp(host_address), chunk_size).await
}

/// Scans a stream for viruses using a TCP connection
///
/// This function sends the provided stream to a ClamAV server through a TCP
/// connection for scanning.
///
/// # Arguments
///
/// * `input_stream`: The stream to be scanned
/// * `host_address`: The address (host and port) of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
#[cfg(feature = "tokio-stream")]
pub async fn scan_stream_tcp<
    S: Stream<Item = Result<bytes::Bytes, io::Error>>,
    A: ToSocketAddrs,
>(
    input_stream: S,
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_stream(input_stream, Tcp(host_address), chunk_size).await
}

/// The address (host and port) of the ClamAV server
pub struct Tcp<A: ToSocketAddrs>(pub A);

/// The path to the Unix socket of the ClamAV server
#[cfg(unix)]
pub struct Socket<P: AsRef<Path>>(pub P);

/// TODO: Add comment
#[async_trait(?Send)]
pub trait AsyncTransportProtocol {
    /// TODO: Add comment
    type Stream: AsyncRead + AsyncWrite + Unpin;

    /// TODO: Add comment
    async fn to_stream(&self) -> io::Result<Self::Stream>;
}

#[async_trait(?Send)]
impl<A: ToSocketAddrs> AsyncTransportProtocol for Tcp<A> {
    type Stream = TcpStream;

    async fn to_stream(&self) -> io::Result<Self::Stream> {
        TcpStream::connect(&self.0).await
    }
}

#[async_trait(?Send)]
#[cfg(unix)]
impl<P: AsRef<Path>> AsyncTransportProtocol for Socket<P> {
    type Stream = UnixStream;

    async fn to_stream(&self) -> io::Result<Self::Stream> {
        UnixStream::connect(&self.0).await
    }
}

/// Sends a ping request to ClamAV
///
/// This function establishes a connection to a ClamAV server and sends the PING
/// command to it. If the server is available, it responds with [`PONG`].
///
/// # Arguments
///
/// * `transport_protocol`: The protocol to use (either TCP or a Unix socket connection)
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let transport_protocol = clamav_client::tokio::Tcp("localhost:3310");
/// let clamd_available = match clamav_client::tokio::ping(transport_protocol).await {
///     Ok(ping_response) => ping_response == clamav_client::PONG,
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// # }
/// ```
///
pub async fn ping<T: AsyncTransportProtocol>(transport_protocol: T) -> IoResult {
    let stream = transport_protocol.to_stream().await?;
    _ping(stream).await
}

/// Scans a file for viruses
///
/// This function reads data from a file located at the specified `file_path`
/// and streams it to a ClamAV server for scanning.
///
/// # Arguments
///
/// * `file_path`: The path to the file to be scanned
/// * `transport_protocol`: The protocol to use (either TCP or a Unix socket connection)
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
pub async fn scan_file<P: AsRef<Path>, T: AsyncTransportProtocol>(
    file_path: P,
    transport_protocol: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let file = File::open(file_path).await?;
    let stream = transport_protocol.to_stream().await?;
    scan(file, chunk_size, stream).await
}

/// Scans a data buffer for viruses
///
/// This function streams the provided `buffer` data to a ClamAV server
///
/// # Arguments
///
/// * `buffer`: The data to be scanned
/// * `transport_protocol`: The protocol to use (either TCP or a Unix socket connection)
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
pub async fn scan_buffer<T: AsyncTransportProtocol>(
    buffer: &[u8],
    transport_protocol: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let stream = transport_protocol.to_stream().await?;
    scan(buffer, chunk_size, stream).await
}

/// Scans a stream for viruses
///
/// This function sends the provided stream to a ClamAV server for scanning.
///
/// # Arguments
///
/// * `input_stream`: The stream to be scanned
/// * `transport_protocol`: The protocol to use (either TCP or a Unix socket connection)
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
#[cfg(feature = "tokio-stream")]
pub async fn scan_stream<
    S: Stream<Item = Result<bytes::Bytes, io::Error>>,
    T: AsyncTransportProtocol,
>(
    input_stream: S,
    transport_protocol: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let output_stream = transport_protocol.to_stream().await?;
    _scan_stream(input_stream, chunk_size, output_stream).await
}
