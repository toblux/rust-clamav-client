use std::path::Path;
use tokio::{
    fs::File,
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrs},
};

#[cfg(feature = "tokio-stream")]
use tokio_stream::{Stream, StreamExt};

use super::{IoResult, DEFAULT_CHUNK_SIZE};

async fn ping<RW: AsyncRead + AsyncWrite + Unpin>(mut stream: RW) -> IoResult {
    stream.write_all(b"zPING\0").await?;

    let capacity = b"PONG\0".len();
    let mut response = Vec::with_capacity(capacity);
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

async fn scan<R: AsyncRead + Unpin, RW: AsyncRead + AsyncWrite + Unpin>(
    mut input: R,
    chunk_size: Option<usize>,
    mut stream: RW,
) -> IoResult {
    stream.write_all(b"zINSTREAM\0").await?;

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
            stream.write_all(&[0; 4]).await?;
            break;
        }
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

#[cfg(feature = "tokio-stream")]
async fn scan_stream<
    S: Stream<Item = Result<bytes::Bytes, std::io::Error>>,
    RW: AsyncRead + AsyncWrite + Unpin,
>(
    input_stream: S,
    chunk_size: Option<usize>,
    mut output_stream: RW,
) -> IoResult {
    output_stream.write_all(b"zINSTREAM\0").await?;

    let chunk_size = chunk_size
        .unwrap_or(DEFAULT_CHUNK_SIZE)
        .min(u32::MAX as usize);

    tokio::pin!(input_stream);

    while let Some(bytes) = input_stream.next().await {
        let bytes = bytes?;
        let bytes = bytes.as_ref();
        for chunk in bytes.chunks(chunk_size) {
            let len = chunk.len();
            output_stream.write_all(&(len as u32).to_be_bytes()).await?;
            output_stream.write_all(chunk).await?;
        }
    }

    output_stream.write_all(&[0; 4]).await?;

    let mut response = Vec::new();
    output_stream.read_to_end(&mut response).await?;
    Ok(response)
}

/// Sends a ping request to ClamAV using a Unix socket connection
///
/// This function establishes a Unix socket connection to a ClamAV server at the
/// specified `socket_path` and sends a ping request to it.
///
/// # Example
///
/// ```
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() {
/// let clamd_available = match clamav_client::tokio::ping_socket("/tmp/clamd.socket").await {
///     Ok(ping_response) => ping_response == b"PONG\0",
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// # }
/// ```
///
#[cfg(unix)]
pub async fn ping_socket<P: AsRef<Path>>(socket_path: P) -> IoResult {
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await?;
    ping(stream).await
}

/// Scans a file for viruses using a Unix socket connection
///
/// This function reads data from a file located at the specified `path` and
/// streams it to a ClamAV server through a Unix socket connection for scanning.
///
/// # Arguments
///
/// * `path`: Path to the file to be scanned
/// * `socket_path`: Path to the Unix socket for the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
#[cfg(unix)]
pub async fn scan_file_socket<P: AsRef<Path>>(
    path: P,
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    use tokio::net::UnixStream;

    let file = File::open(path).await?;
    let stream = UnixStream::connect(socket_path).await?;
    scan(file, chunk_size, stream).await
}

/// Scans a data buffer for viruses using a Unix socket connection
///
/// This function streams the provided `buffer` data to a ClamAV server through
/// a Unix socket connection for scanning.
///
/// # Arguments
///
/// * `buffer`: The data to be scanned
/// * `socket_path`: The path to the Unix socket for the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
#[cfg(unix)]
pub async fn scan_buffer_socket<P: AsRef<Path>>(
    buffer: &[u8],
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path).await?;
    scan(buffer, chunk_size, stream).await
}

/// Scans a stream for viruses using a Unix socket connection
///
/// This function sends the provided stream to a ClamAV server through a Unix
/// socket connection for scanning.
///
/// # Arguments
///
/// * `input_stream`: The stream to be scanned
/// * `socket_path`: The path to the Unix socket for the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
#[cfg(all(unix, feature = "tokio-stream"))]
pub async fn scan_stream_socket<
    S: Stream<Item = Result<bytes::Bytes, std::io::Error>>,
    P: AsRef<Path>,
>(
    input_stream: S,
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    use tokio::net::UnixStream;

    let output_stream = UnixStream::connect(socket_path).await?;
    scan_stream(input_stream, chunk_size, output_stream).await
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
///     Ok(ping_response) => ping_response == b"PONG\0",
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// # }
/// ```
///
pub async fn ping_tcp<A: ToSocketAddrs>(host_address: A) -> IoResult {
    let stream = TcpStream::connect(host_address).await?;
    ping(stream).await
}

/// Scans a file for viruses using a TCP connection
///
/// This function reads data from a file located at the specified `path` and
/// streams it to a ClamAV server through a TCP connection for scanning.
///
/// # Arguments
///
/// * `path`: The path to the file to be scanned
/// * `host_address`: The address (host and port) of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
pub async fn scan_file_tcp<P: AsRef<Path>, A: ToSocketAddrs>(
    path: P,
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    let file = File::open(path).await?;
    let stream = TcpStream::connect(host_address).await?;
    scan(file, chunk_size, stream).await
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
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
pub async fn scan_buffer_tcp<A: ToSocketAddrs>(
    buffer: &[u8],
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    let stream = TcpStream::connect(host_address).await?;
    scan(buffer, chunk_size, stream).await
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
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
#[cfg(feature = "tokio-stream")]
pub async fn scan_stream_tcp<
    S: Stream<Item = Result<bytes::Bytes, std::io::Error>>,
    A: ToSocketAddrs,
>(
    input_stream: S,
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    let output_stream = TcpStream::connect(host_address).await?;
    scan_stream(input_stream, chunk_size, output_stream).await
}
