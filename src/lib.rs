use std::{
    fs::File,
    io::{Error, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    result::Result,
    str::{from_utf8, Utf8Error},
};

type IoResult = Result<Vec<u8>, Error>;
type Utf8Result = Result<bool, Utf8Error>;

const DEFAULT_CHUNK_SIZE: u32 = 4096; // 4 kibibytes

fn ping<RW>(mut stream: RW) -> IoResult
where
    RW: Read + Write,
{
    stream.write_all(b"zPING\0")?;

    let capacity = b"PONG\0".len();
    let mut response = Vec::with_capacity(capacity);
    stream.read_to_end(&mut response)?;
    Ok(response)
}

fn scan<P, RW>(file_path: P, chunk_size: Option<u32>, mut stream: RW) -> IoResult
where
    P: AsRef<Path>,
    RW: Read + Write,
{
    stream.write_all(b"zINSTREAM\0")?;

    let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0; chunk_size as usize];
    loop {
        let len = file.read(&mut buffer[..])?;
        if len != 0 {
            stream.write_all(&(len as u32).to_be_bytes())?;
            stream.write_all(&buffer[0..len])?;
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
pub fn ping_socket<P>(socket_path: P) -> IoResult
where
    P: AsRef<Path>,
{
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path)?;
    ping(stream)
}

#[cfg(target_family = "unix")]
pub fn scan_socket<P>(file_path: P, socket_path: P, chunk_size: Option<u32>) -> IoResult
where
    P: AsRef<Path>,
{
    use std::os::unix::net::UnixStream;

    let stream = UnixStream::connect(socket_path)?;
    scan(file_path, chunk_size, stream)
}

pub fn ping_tcp<A>(host_address: A) -> IoResult
where
    A: ToSocketAddrs,
{
    let stream = TcpStream::connect(host_address)?;
    ping(stream)
}

pub fn scan_tcp<P, A>(file_path: P, host_address: A, chunk_size: Option<u32>) -> IoResult
where
    A: ToSocketAddrs,
    P: AsRef<Path>,
{
    let stream = TcpStream::connect(host_address)?;
    scan(file_path, chunk_size, stream)
}

pub fn clean(response: &[u8]) -> Utf8Result {
    let response = from_utf8(response)?;
    Ok(response.contains("OK") && !response.contains("FOUND"))
}
