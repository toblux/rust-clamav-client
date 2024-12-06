#![doc = include_str!("../README.md")]
#![deny(missing_docs)]

use std::{net::ToSocketAddrs, path::Path};

#[cfg(feature = "tokio")]
/// Use the feature flag "tokio" or "tokio-stream" to enable this module
pub mod tokio;

#[cfg(feature = "async-std")]
/// Use the feature flag "async-std" to enable this module
pub mod async_std;

/// Blocking
pub mod blocking;

/// Nonblocking
pub mod nonblocking;

/// Custom result type
pub type IoResult = Result<Vec<u8>, std::io::Error>;

/// Custom result type
pub type Utf8Result = Result<bool, std::str::Utf8Error>;

/// Default chunk size in bytes for reading data during scanning
const DEFAULT_CHUNK_SIZE: usize = 4096;

/// ClamAV commands
const PING: &[u8; 6] = b"zPING\0";
const VERSION: &[u8; 9] = b"zVERSION\0";
const SHUTDOWN: &[u8; 10] = b"zSHUTDOWN\0";
const INSTREAM: &[u8; 10] = b"zINSTREAM\0";
const END_OF_STREAM: &[u8; 4] = &[0, 0, 0, 0];

/// ClamAV's response to a PING request
pub const PONG: &[u8; 5] = b"PONG\0";

pub use blocking::{get_version, ping, scan_buffer, scan_file};

/// Use a TCP connection to communicate with a ClamAV server
#[derive(Debug, Clone, Copy)]
pub struct Tcp<T: ToSocketAddrs> {
    /// The address (host and port) of the ClamAV server
    pub host_address: T,
}

/// Use a Unix socket connection to communicate with a ClamAV server
#[derive(Debug, Clone, Copy)]
#[cfg(unix)]
pub struct Socket<P: AsRef<Path>> {
    /// The socket file path of the ClamAV server
    pub socket_path: P,
}

/// Checks whether the ClamAV response indicates that the scanned content is
/// clean or contains a virus
///
/// # Example
///
/// ```
/// let clamd_tcp = clamav_client::Tcp{ host_address: "localhost:3310" };
/// let response = clamav_client::scan_buffer(br#"clean data"#, clamd_tcp, None).unwrap();
/// let data_clean = clamav_client::clean(&response).unwrap();
/// # assert_eq!(data_clean, true);
/// ```
///
/// # Returns
///
/// An [`Utf8Result`] containing the scan result as [`bool`]
///
pub fn clean(response: &[u8]) -> Utf8Result {
    let response = std::str::from_utf8(response)?;
    Ok(response.contains("OK") && !response.contains("FOUND"))
}
