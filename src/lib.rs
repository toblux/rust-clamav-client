#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[cfg(feature = "tokio")]
/// Use the feature flag "tokio" or "tokio-stream" to enable this module
pub mod tokio;

#[cfg(feature = "async-std")]
/// Use the feature flag "async-std" to enable this module
pub mod async_std;

use std::{
    fs::File,
    io::{self, Error, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    str::{self, Utf8Error},
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

/// Custom result type
pub type IoResult = Result<Vec<u8>, Error>;

/// Custom result type
pub type Utf8Result = Result<bool, Utf8Error>;

/// Default chunk size in bytes for reading data during scanning
const DEFAULT_CHUNK_SIZE: usize = 4096;

/// ClamAV commands
const PING: &[u8; 6] = b"zPING\0";
const VERSION: &[u8; 9] = b"zVERSION\0";
const INSTREAM: &[u8; 10] = b"zINSTREAM\0";
const END_OF_STREAM: &[u8; 4] = &[0, 0, 0, 0];

/// ClamAV's response to a PING request
pub const PONG: &[u8; 5] = b"PONG\0";

fn send_command<RW: Read + Write>(
    mut stream: RW,
    command: &[u8],
    expected_response_length: Option<usize>,
) -> IoResult {
    stream.write_all(command)?;
    stream.flush()?;

    let mut response = match expected_response_length {
        Some(len) => Vec::with_capacity(len),
        None => Vec::new(),
    };

    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn _ping<RW: Read + Write>(stream: RW) -> IoResult {
    send_command(stream, PING, Some(PONG.len()))
}

fn _get_version<RW: Read + Write>(stream: RW) -> IoResult {
    send_command(stream, VERSION, None)
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
            stream.flush()?;
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
/// specified `socket_path` and sends the PING command to it. If the server
/// is available, it responds with [`PONG`].
///
/// # Arguments
///
/// * `socket_path`: Path to the Unix socket for the ClamAV server
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// let clamd_available = match clamav_client::ping_socket("/tmp/clamd.socket") {
///     Ok(ping_response) => ping_response == clamav_client::PONG,
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// ```
///
#[deprecated(since = "0.5.0", note = "Use `ping` instead")]
#[cfg(unix)]
pub fn ping_socket<P: AsRef<Path>>(socket_path: P) -> IoResult {
    ping(Socket(socket_path))
}

/// Gets the version number from ClamAV using a Unix socket connection
///
/// This function establishes a Unix socket connection to a ClamAV server at the
/// specified `socket_path` and sends the VERSION command to it. If the
/// server is available, it responds with its version number.
///
/// # Arguments
///
/// * `socket_path`: Path to the Unix socket for the ClamAV server
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// let version = clamav_client::get_version_socket("/tmp/clamd.socket").unwrap();
/// # assert!(version.starts_with(b"ClamAV"));
/// ```
///
#[deprecated(since = "0.5.0", note = "Use `get_version` instead")]
#[cfg(unix)]
pub fn get_version_socket<P: AsRef<Path>>(socket_path: P) -> IoResult {
    get_version(Socket(socket_path))
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
#[deprecated(since = "0.5.0", note = "Use `scan_file` instead")]
#[cfg(unix)]
pub fn scan_file_socket<P: AsRef<Path>>(
    file_path: P,
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_file(file_path, Socket(socket_path), chunk_size)
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
#[deprecated(since = "0.5.0", note = "Use `scan_buffer` instead")]
#[cfg(unix)]
pub fn scan_buffer_socket<P: AsRef<Path>>(
    buffer: &[u8],
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_buffer(buffer, Socket(socket_path), chunk_size)
}

/// Sends a ping request to ClamAV using a TCP connection
///
/// This function establishes a TCP connection to a ClamAV server at the
/// specified `host_address` and sends the PING command to it. If
/// the server is available, it responds with [`PONG`].
///
/// # Arguments
///
/// * `host_address`: The address (host and port) of the ClamAV server
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// let clamd_available = match clamav_client::ping_tcp("localhost:3310") {
///     Ok(ping_response) => ping_response == clamav_client::PONG,
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// ```
///
#[deprecated(since = "0.5.0", note = "Use `ping` instead")]
pub fn ping_tcp<A: ToSocketAddrs>(host_address: A) -> IoResult {
    ping(Tcp(host_address))
}

/// Gets the version number from ClamAV using a TCP connection
///
/// This function establishes a TCP connection to a ClamAV server at the
/// specified `host_address` and sends the VERSION command to it. If the
/// server is available, it responds with its version number.
///
/// # Arguments
///
/// * `host_address`: The address (host and port) of the ClamAV server
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// let version = clamav_client::get_version_tcp("localhost:3310").unwrap();
/// # assert!(version.starts_with(b"ClamAV"));
/// ```
///
#[deprecated(since = "0.5.0", note = "Use `get_version` instead")]
pub fn get_version_tcp<A: ToSocketAddrs>(host_address: A) -> IoResult {
    get_version(Tcp(host_address))
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
#[deprecated(since = "0.5.0", note = "Use `scan_file` instead")]
pub fn scan_file_tcp<P: AsRef<Path>, A: ToSocketAddrs>(
    file_path: P,
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_file(file_path, Tcp(host_address), chunk_size)
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
#[deprecated(since = "0.5.0", note = "Use `scan_buffer` instead")]
pub fn scan_buffer_tcp<A: ToSocketAddrs>(
    buffer: &[u8],
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    scan_buffer(buffer, Tcp(host_address), chunk_size)
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
/// # Returns
///
/// An [`Utf8Result`] containing the scan result as [`bool`]
///
pub fn clean(response: &[u8]) -> Utf8Result {
    let response = str::from_utf8(response)?;
    Ok(response.contains("OK") && !response.contains("FOUND"))
}

/// The communication protocol to use
pub trait TransportProtocol {
    /// Bidirectional stream
    type Stream: Read + Write;

    /// Converts the protocol instance into the corresponding stream
    fn to_stream(&self) -> io::Result<Self::Stream>;
}

/// The address (host and port) of the ClamAV server
#[derive(Copy, Clone)]
pub struct Tcp<A: ToSocketAddrs>(pub A);

/// The path to the Unix socket of the ClamAV server
#[derive(Copy, Clone)]
#[cfg(unix)]
pub struct Socket<P: AsRef<Path>>(pub P);

impl<A: ToSocketAddrs> TransportProtocol for Tcp<A> {
    type Stream = TcpStream;

    fn to_stream(&self) -> io::Result<Self::Stream> {
        TcpStream::connect(&self.0)
    }
}

#[cfg(unix)]
impl<P: AsRef<Path>> TransportProtocol for Socket<P> {
    type Stream = UnixStream;

    fn to_stream(&self) -> io::Result<Self::Stream> {
        UnixStream::connect(&self.0)
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
/// let transport_protocol = clamav_client::Tcp("localhost:3310");
/// let clamd_available = match clamav_client::ping(transport_protocol) {
///     Ok(ping_response) => ping_response == clamav_client::PONG,
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// ```
///
pub fn ping<T: TransportProtocol>(transport_protocol: T) -> IoResult {
    let stream = transport_protocol.to_stream()?;
    _ping(stream)
}

/// Gets the version number from ClamAV
///
/// This function establishes a connection to a ClamAV server and sends the
/// VERSION command to it. If the server is available, it responds with its
/// version number.
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
/// let transport_protocol = clamav_client::Tcp("localhost:3310");
/// let version = clamav_client::get_version(transport_protocol).unwrap();
/// # assert!(version.starts_with(b"ClamAV"));
/// ```
///
pub fn get_version<T: TransportProtocol>(transport_protocol: T) -> IoResult {
    let stream = transport_protocol.to_stream()?;
    _get_version(stream)
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
pub fn scan_file<P: AsRef<Path>, T: TransportProtocol>(
    file_path: P,
    transport_protocol: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let file = File::open(file_path)?;
    let stream = transport_protocol.to_stream()?;
    scan(file, chunk_size, stream)
}

/// Scans a data buffer for viruses
///
/// This function streams the provided `buffer` data to a ClamAV server for
/// scanning.
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
pub fn scan_buffer<T: TransportProtocol>(
    buffer: &[u8],
    transport_protocol: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let stream = transport_protocol.to_stream()?;
    scan(buffer, chunk_size, stream)
}
