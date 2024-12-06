use std::{
    fs::File,
    io::{Read, Write},
    net::TcpStream,
    path::Path,
};

#[cfg(unix)]
use std::os::unix::net::UnixStream;

use crate::{
    IoResult, Socket, Tcp, DEFAULT_CHUNK_SIZE, END_OF_STREAM, INSTREAM, PING, PONG, SHUTDOWN,
    VERSION,
};

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

/// The communication protocol to use
pub trait TransportProtocol {
    /// Bidirectional stream
    type Stream: Read + Write;

    /// Converts the protocol instance into the corresponding stream
    fn connect(&self) -> std::io::Result<Self::Stream>;
}

impl<A: std::net::ToSocketAddrs> TransportProtocol for Tcp<A> {
    type Stream = TcpStream;

    fn connect(&self) -> std::io::Result<Self::Stream> {
        TcpStream::connect(&self.host_address)
    }
}

#[cfg(unix)]
impl<P: AsRef<Path>> TransportProtocol for Socket<P> {
    type Stream = UnixStream;

    fn connect(&self) -> std::io::Result<Self::Stream> {
        UnixStream::connect(&self.socket_path)
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
