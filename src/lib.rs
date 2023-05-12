use std::{
    fs::File,
    io::{Error, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    result::Result,
    str::Utf8Error,
};

pub type IoResult = Result<Vec<u8>, Error>;
pub type Utf8Result = Result<bool, Utf8Error>;

const DEFAULT_CHUNK_SIZE: usize = 4096; // 4 kibibytes

fn ping<RW: Read + Write>(mut stream: RW) -> IoResult {
    stream.write_all(b"zPING\0")?;

    let capacity = b"PONG\0".len();
    let mut response = Vec::with_capacity(capacity);
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn scan<R: Read, RW: Read + Write>(
    mut input: R,
    chunk_size: Option<usize>,
    mut stream: RW,
) -> IoResult {
    stream.write_all(b"zINSTREAM\0")?;

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
            stream.write_all(&[0; 4])?;
            break;
        }
    }

    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(response)
}

#[cfg(target_family = "unix")]
pub fn ping_socket<P: AsRef<Path>>(socket_path: P) -> IoResult {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path)?;
    ping(stream)
}

#[cfg(target_family = "unix")]
pub fn scan_file_socket<P: AsRef<Path>>(
    path: P,
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    use std::os::unix::net::UnixStream;

    let file = File::open(path)?;
    let stream = UnixStream::connect(socket_path)?;
    scan(file, chunk_size, stream)
}

#[cfg(target_family = "unix")]
pub fn scan_buffer_socket<P: AsRef<Path>>(
    buffer: &[u8],
    socket_path: P,
    chunk_size: Option<usize>,
) -> IoResult {
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path)?;
    scan(buffer, chunk_size, stream)
}

pub fn ping_tcp<A: ToSocketAddrs>(host_address: A) -> IoResult {
    let stream = TcpStream::connect(host_address)?;
    ping(stream)
}

pub fn scan_file_tcp<P: AsRef<Path>, A: ToSocketAddrs>(
    path: P,
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    let file = File::open(path)?;
    let stream = TcpStream::connect(host_address)?;
    scan(file, chunk_size, stream)
}

pub fn scan_buffer_tcp<A: ToSocketAddrs>(
    buffer: &[u8],
    host_address: A,
    chunk_size: Option<usize>,
) -> IoResult {
    let stream = TcpStream::connect(host_address)?;
    scan(buffer, chunk_size, stream)
}

pub fn clean(response: &[u8]) -> Utf8Result {
    let response = std::str::from_utf8(response)?;
    Ok(response.contains("OK") && !response.contains("FOUND"))
}
