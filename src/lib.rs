#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[cfg(feature = "tokio")]
/// Async Tokio implementation
pub mod tokio;

#[cfg(feature = "async-std")]
/// async-std implementation
pub mod async_std;

use std::{
    fs::File,
    io::{Error, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    str::Utf8Error,
};

/// TODO: Add comment
pub type IoResult = Result<Vec<u8>, Error>;

/// TODO: Add comment
pub type Utf8Result = Result<bool, Utf8Error>;

/// Default chunk size in bytes for reading data during scanning
const DEFAULT_CHUNK_SIZE: usize = 4096;

/// ClamAV commands
const PING: &[u8; 6] = b"zPING\0";
const PONG: &[u8; 5] = b"PONG\0";
const INSTREAM: &[u8; 10] = b"zINSTREAM\0";
const END_OF_STREAM: &[u8; 4] = &[0, 0, 0, 0];

fn ping<RW: Read + Write>(mut stream: RW) -> IoResult {
    stream.write_all(PING)?;

    let capacity = PONG.len();
    let mut response = Vec::with_capacity(capacity);
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn scan<R: Read, RW: Read + Write>(
    mut input: R,
    chunk_size: Option<usize>,
    mut stream: RW,
) -> IoResult {
    stream.write_all(INSTREAM)?;

    let chunk_size = chunk_size
        .unwrap_or(DEFAULT_CHUNK_SIZE)
        .min(u32::MAX as usize);
    let mut buffer = vec![0; chunk_size];
    loop {
        let len = input.read(&mut buffer[..])?;
        if len != 0 {
            stream.write_all(&(len as u32).to_be_bytes())?;
            stream.write_all(&buffer[..len])?;
        } else {
            stream.write_all(END_OF_STREAM)?;
            break;
        }
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
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
/// let clamd_available = match clamav_client::ping_socket("/tmp/clamd.socket") {
///     Ok(ping_response) => ping_response == b"PONG\0",
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// ```
///
#[cfg(unix)]
pub fn ping_socket<P: AsRef<Path>>(socket_path: P) -> IoResult {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path)?;
    ping(stream)
}

/// Scans a file for viruses using a Unix socket connection
///
/// This function reads data from a file located at the specified `path` and
/// streams it to a ClamAV server through a Unix socket connection for scanning.
///
/// # Arguments
///
/// * `file_path`: Path to the file to be scanned
/// * `socket_path`: Path to the Unix socket for the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
#[cfg(unix)]
pub fn scan_file_socket<P: AsRef<Path>>(
    file_path: P,
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    use std::os::unix::net::UnixStream;

    let file = File::open(file_path)?;
    let stream = UnixStream::connect(socket_path)?;
    scan(file, chunk_size, stream)
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
pub fn scan_buffer_socket<P: AsRef<Path>>(
    buffer: &[u8],
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path)?;
    scan(buffer, chunk_size, stream)
}

/// Sends a ping request to ClamAV using a TCP connection
///
/// This function establishes a TCP connection to a ClamAV server at the
/// specified `host_address` and sends a ping request to it.
///
/// # Example
///
/// ```
/// let clamd_available = match clamav_client::ping_tcp("localhost:3310") {
///     Ok(ping_response) => ping_response == b"PONG\0",
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// ```
///
pub fn ping_tcp<A: ToSocketAddrs>(host_address: A) -> IoResult {
    let stream = TcpStream::connect(host_address)?;
    ping(stream)
}

/// Scans a file for viruses using a TCP connection
///
/// This function reads data from a file located at the specified `path` and
/// streams it to a ClamAV server through a TCP connection for scanning.
///
/// # Arguments
///
/// * `file_path`: The path to the file to be scanned
/// * `host_address`: The address (host and port) of the ClamAV server
/// * `chunk_size`: An optional chunk size for reading data. If `None`, a default chunk size is used
///
/// # Returns
///
/// An `IoResult` containing the server's response as a vector of bytes
///
pub fn scan_file_tcp<P: AsRef<Path>, A: ToSocketAddrs>(
    file_path: P,
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    let file = File::open(file_path)?;
    let stream = TcpStream::connect(host_address)?;
    scan(file, chunk_size, stream)
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
pub fn scan_buffer_tcp<A: ToSocketAddrs>(
    buffer: &[u8],
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    let stream = TcpStream::connect(host_address)?;
    scan(buffer, chunk_size, stream)
}

/// Checks whether the ClamAV response indicates that the scanned content is
/// clean or contains a virus
///
/// # Example
///
/// ```
/// let response = clamav_client::scan_buffer_tcp(br#"clean data"#, "localhost:3310", None).unwrap();
/// let data_clean = clamav_client::clean(&response).unwrap();
/// # assert_eq!(data_clean, true);
/// ```
///
pub fn clean(response: &[u8]) -> Utf8Result {
    let response = std::str::from_utf8(response)?;
    Ok(response.contains("OK") && !response.contains("FOUND"))
}
