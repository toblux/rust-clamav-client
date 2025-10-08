#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

#[cfg(feature = "tokio")]
/// Use the feature flag "tokio" or "tokio-stream" to enable this module
pub mod tokio;

#[cfg(feature = "async-std")]
/// Use the feature flag "async-std" to enable this module
pub mod async_std;

#[cfg(feature = "smol")]
/// Use the feature flag "smol" to enable this module
pub mod smol;

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
const RELOAD: &[u8; 8] = b"zRELOAD\0";
const VERSION: &[u8; 9] = b"zVERSION\0";
const SHUTDOWN: &[u8; 10] = b"zSHUTDOWN\0";
const INSTREAM: &[u8; 10] = b"zINSTREAM\0";
const END_OF_STREAM: &[u8; 4] = &[0, 0, 0, 0];

/// ClamAV's response to a PING request
pub const PONG: &[u8; 5] = b"PONG\0";

/// ClamAV's response to a RELOAD request
pub const RELOADING: &[u8; 10] = b"RELOADING\0";

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

/// Checks whether the ClamAV response indicates that the scanned content is
/// clean or contains a virus
///
/// # Example
///
/// ```
/// let clamd_tcp = clamav_client::Tcp{ host_address: "localhost:3310" };
/// let response = clamav_client::scan_buffer(b"clean data", clamd_tcp, None).unwrap();
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

/// Use a TCP connection to communicate with a ClamAV server
#[derive(Copy, Clone)]
pub struct Tcp<A: ToSocketAddrs> {
    /// The address (host and port) of the ClamAV server
    pub host_address: A,
}

/// Use a Unix socket connection to communicate with a ClamAV server
#[derive(Copy, Clone)]
#[cfg(unix)]
pub struct Socket<P: AsRef<Path>> {
    /// The socket file path of the ClamAV server
    pub socket_path: P,
}

/// The communication protocol to use
pub trait TransportProtocol {
    /// Bidirectional stream
    type Stream: Read + Write;

    /// Converts the protocol instance into the corresponding stream
    fn connect(&self) -> io::Result<Self::Stream>;
}

impl<A: ToSocketAddrs> TransportProtocol for Tcp<A> {
    type Stream = TcpStream;

    fn connect(&self) -> io::Result<Self::Stream> {
        TcpStream::connect(&self.host_address)
    }
}

#[cfg(unix)]
impl<P: AsRef<Path>> TransportProtocol for Socket<P> {
    type Stream = UnixStream;

    fn connect(&self) -> io::Result<Self::Stream> {
        UnixStream::connect(&self.socket_path)
    }
}

impl<T> TransportProtocol for &T
where
    T: TransportProtocol,
{
    type Stream = T::Stream;

    fn connect(&self) -> io::Result<Self::Stream> {
        TransportProtocol::connect(*self)
    }
}

/// Sends a ping request to ClamAV
///
/// This function establishes a connection to a ClamAV server and sends the PING
/// command to it. If the server is available, it responds with [`PONG`].
///
/// # Arguments
///
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// let clamd_tcp = clamav_client::Tcp{ host_address: "localhost:3310" };
/// let clamd_available = match clamav_client::ping(clamd_tcp) {
///     Ok(ping_response) => ping_response == clamav_client::PONG,
///     Err(_) => false,
/// };
/// # assert!(clamd_available);
/// ```
///
pub fn ping<T: TransportProtocol>(connection: T) -> IoResult {
    let stream = connection.connect()?;
    send_command(stream, PING, Some(PONG.len()))
}

/// Reloads the virus databases
///
/// This function establishes a connection to a ClamAV server and sends the
/// RELOAD command to it. If the server is available, it responds with
/// [`RELOADING`].
///
/// # Arguments
///
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// let clamd_tcp = clamav_client::Tcp{ host_address: "localhost:3310" };
/// let response = clamav_client::reload(clamd_tcp).unwrap();
/// # assert!(response == clamav_client::RELOADING);
/// ```
///
pub fn reload<T: TransportProtocol>(connection: T) -> IoResult {
    let stream = connection.connect()?;
    send_command(stream, RELOAD, Some(RELOADING.len()))
}

/// Gets the version number from ClamAV
///
/// This function establishes a connection to a ClamAV server and sends the
/// VERSION command to it. If the server is available, it responds with its
/// version number.
///
/// # Arguments
///
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
/// # Example
///
/// ```
/// let clamd_tcp = clamav_client::Tcp{ host_address: "localhost:3310" };
/// let version = clamav_client::get_version(clamd_tcp).unwrap();
/// # assert!(version.starts_with(b"ClamAV"));
/// ```
///
pub fn get_version<T: TransportProtocol>(connection: T) -> IoResult {
    let stream = connection.connect()?;
    send_command(stream, VERSION, None)
}

/// Scans a file for viruses
///
/// This function reads data from a file located at the specified `file_path`
/// and streams it to a ClamAV server for scanning.
///
/// # Arguments
///
/// * `file_path`: The path to the file to be scanned
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
pub fn scan_file<P: AsRef<Path>, T: TransportProtocol>(
    file_path: P,
    connection: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let file = File::open(file_path)?;
    let stream = connection.connect()?;
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
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
/// * `chunk_size`: An optional chunk size for reading data. If [`None`], a default chunk size is used
///
/// # Returns
///
/// An [`IoResult`] containing the server's response as a vector of bytes
///
pub fn scan_buffer<T: TransportProtocol>(
    buffer: &[u8],
    connection: T,
    chunk_size: Option<usize>,
) -> IoResult {
    let stream = connection.connect()?;
    scan(buffer, chunk_size, stream)
}

/// Shuts down a ClamAV server
///
/// This function establishes a connection to a ClamAV server and sends the
/// SHUTDOWN command to it. If the server is available, it will perform a clean
/// exit and shut itself down. The response will be empty.
///
/// # Arguments
///
/// * `connection`: The connection type to use - either TCP or a Unix socket connection
///
/// # Returns
///
/// An [`IoResult`] containing the server's response
///
pub fn shutdown<T: TransportProtocol>(connection: T) -> IoResult {
    let stream = connection.connect()?;
    send_command(stream, SHUTDOWN, None)
}
