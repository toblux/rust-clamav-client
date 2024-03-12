#[cfg(unix)]
const TEST_SOCKET_PATH: &str = "/tmp/clamd.socket";
const TEST_HOST_ADDRESS: &str = "localhost:3310";
const EICAR_TEST_FILE_PATH: &str = "tests/data/eicar.txt";
const CLEAN_TEST_FILE_PATH: &str = "README.md";

const EICAR_FILE_SIGNATURE_FOUND_RESPONSE: &[u8] = b"stream: Eicar-Signature FOUND\0";
const OK_RESPONSE: &[u8] = b"stream: OK\0";

// `StreamMaxLength` is limited to 1 MB (1_000_000 bytes) in `clamd.conf` - this
// binary test file is 1 byte larger than allowed (1_000_001 bytes in total) to
// test ClamAV's "size limit exceeded" error. The file was created using the
// truncate utility: `truncate -s 1000001 filename`
const OVERSIZED_TEST_FILE_PATH: &str = "tests/data/stream-max-length-test-file.bin";
const SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE: &[u8] = b"INSTREAM size limit exceeded. ERROR\0";

mod lib_tests {
    use super::*;

    const CLAMD_HOST_TCP: clamav_client::Tcp<&str> = clamav_client::Tcp {
        host_address: TEST_HOST_ADDRESS,
    };

    #[cfg(unix)]
    const CLAMD_HOST_SOCKET: clamav_client::Socket<&str> = clamav_client::Socket {
        socket_path: TEST_SOCKET_PATH,
    };

    #[test]
    fn ping_socket() {
        let err_msg = format!(
            "Could not ping clamd via Unix socket at {}",
            CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::ping(CLAMD_HOST_SOCKET).expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[test]
    #[cfg(unix)]
    fn get_version_socket() {
        let err_msg = format!(
            "Could not get ClamAV version via Unix socket at {}",
            CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::get_version(CLAMD_HOST_SOCKET).expect(&err_msg);
        assert!(&response.starts_with(b"ClamAV"));
    }

    #[test]
    #[cfg(unix)]
    fn scan_socket_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::scan_file(EICAR_TEST_FILE_PATH, CLAMD_HOST_SOCKET, None)
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[test]
    #[cfg(unix)]
    fn scan_socket_infected_buffer() {
        let err_msg = format!(
            "Could not scan EICAR test string via socket at {}",
            CLAMD_HOST_SOCKET.socket_path
        );
        let buffer = include_bytes!("data/eicar.txt");
        let response = clamav_client::scan_buffer(buffer, CLAMD_HOST_SOCKET, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[test]
    #[cfg(unix)]
    fn scan_socket_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::scan_file(CLEAN_TEST_FILE_PATH, CLAMD_HOST_SOCKET, None)
            .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[test]
    #[cfg(unix)]
    fn scan_socket_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::scan_file(OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_SOCKET, None)
            .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[test]
    fn ping_tcp() {
        let err_msg = format!(
            "Could not ping clamd via TCP at {}",
            CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::ping(CLAMD_HOST_TCP).expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[test]
    fn get_version_tcp() {
        let err_msg = format!(
            "Could not get ClamAV version via TCP at {}",
            CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::get_version(CLAMD_HOST_TCP).expect(&err_msg);
        assert!(&response.starts_with(b"ClamAV"));
    }

    #[test]
    fn scan_tcp_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response =
            clamav_client::scan_file(EICAR_TEST_FILE_PATH, CLAMD_HOST_TCP, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[test]
    fn scan_tcp_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response =
            clamav_client::scan_file(CLEAN_TEST_FILE_PATH, CLAMD_HOST_TCP, None).expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[test]
    fn scan_tcp_infected_buffer() {
        let err_msg = format!(
            "Could not scan EICAR test string via TCP at {}",
            CLAMD_HOST_TCP.host_address
        );
        let buffer = include_bytes!("data/eicar.txt");
        let response = clamav_client::scan_buffer(buffer, CLAMD_HOST_TCP, None).expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[test]
    fn scan_tcp_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::scan_file(OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_TCP, None)
            .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(feature = "tokio")]
mod tokio_tests {
    use super::*;

    const CLAMD_HOST_TCP: clamav_client::tokio::Tcp<&str> = clamav_client::tokio::Tcp {
        host_address: TEST_HOST_ADDRESS,
    };

    #[cfg(unix)]
    const CLAMD_HOST_SOCKET: clamav_client::tokio::Socket<&str> = clamav_client::tokio::Socket {
        socket_path: TEST_SOCKET_PATH,
    };

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_ping_socket() {
        let err_msg = format!(
            "Could not ping clamd via Unix socket at {}",
            CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::tokio::ping(CLAMD_HOST_SOCKET)
            .await
            .expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response =
            clamav_client::tokio::scan_file(EICAR_TEST_FILE_PATH, CLAMD_HOST_SOCKET, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_infected_buffer() {
        let err_msg = format!(
            "Could not scan EICAR test string via socket at {}",
            CLAMD_HOST_SOCKET.socket_path
        );
        let buffer = include_bytes!("data/eicar.txt");
        let response = clamav_client::tokio::scan_buffer(buffer, CLAMD_HOST_SOCKET, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response =
            clamav_client::tokio::scan_file(CLEAN_TEST_FILE_PATH, CLAMD_HOST_SOCKET, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response =
            clamav_client::tokio::scan_file(OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_SOCKET, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn async_tokio_ping_tcp() {
        let err_msg = format!(
            "Could not ping clamd via TCP at {}",
            CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::tokio::ping(CLAMD_HOST_TCP)
            .await
            .expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::tokio::scan_file(EICAR_TEST_FILE_PATH, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_infected_buffer() {
        let err_msg = format!(
            "Could not scan EICAR test string via TCP at {}",
            CLAMD_HOST_TCP.host_address
        );
        let buffer = include_bytes!("data/eicar.txt");
        let response = clamav_client::tokio::scan_buffer(buffer, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::tokio::scan_file(CLEAN_TEST_FILE_PATH, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response =
            clamav_client::tokio::scan_file(OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_TCP, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(feature = "tokio-stream")]
mod tokio_stream_tests {
    use super::*;
    use std::path::Path;
    use tokio::fs::File;
    use tokio_util::io::ReaderStream;

    const CLAMD_HOST_TCP: clamav_client::tokio::Tcp<&str> = clamav_client::tokio::Tcp {
        host_address: TEST_HOST_ADDRESS,
    };

    #[cfg(unix)]
    const CLAMD_HOST_SOCKET: clamav_client::tokio::Socket<&str> = clamav_client::tokio::Socket {
        socket_path: TEST_SOCKET_PATH,
    };

    async fn stream_from_file<P: AsRef<Path>>(path: P) -> ReaderStream<File> {
        let path_str = path.as_ref().to_str().expect("Invalid path");
        let err_msg = format!("Could not read test file {}", path_str);
        let file = File::open(path).await.expect(&err_msg);
        ReaderStream::with_capacity(file, 16)
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_infected_stream() {
        let stream = stream_from_file(EICAR_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::tokio::scan_stream(stream, CLAMD_HOST_SOCKET, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_clean_stream() {
        let stream = stream_from_file(CLEAN_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::tokio::scan_stream(stream, CLAMD_HOST_SOCKET, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn async_tokio_scan_socket_oversized_stream() {
        let stream = stream_from_file(OVERSIZED_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::tokio::scan_stream(stream, CLAMD_HOST_SOCKET, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_infected_stream() {
        let stream = stream_from_file(EICAR_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::tokio::scan_stream(stream, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_clean_stream() {
        let stream = stream_from_file(CLEAN_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::tokio::scan_stream(stream, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[tokio::test]
    async fn async_tokio_scan_tcp_oversized_stream() {
        let stream = stream_from_file(OVERSIZED_TEST_FILE_PATH).await;

        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::tokio::scan_stream(stream, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(feature = "async-std")]
mod async_std_tests {
    use super::*;

    const CLAMD_HOST_TCP: clamav_client::async_std::Tcp<&str> = clamav_client::async_std::Tcp {
        host_address: TEST_HOST_ADDRESS,
    };

    #[cfg(unix)]
    const CLAMD_HOST_SOCKET: clamav_client::async_std::Socket<&str> =
        clamav_client::async_std::Socket {
            socket_path: TEST_SOCKET_PATH,
        };

    #[async_std::test]
    #[cfg(unix)]
    async fn async_std_ping_socket() {
        let err_msg = format!(
            "Could not ping clamd via Unix socket at {}",
            CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::async_std::ping(CLAMD_HOST_SOCKET)
            .await
            .expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_std_scan_socket_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response =
            clamav_client::async_std::scan_file(EICAR_TEST_FILE_PATH, CLAMD_HOST_SOCKET, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_std_scan_socket_infected_buffer() {
        let err_msg = format!(
            "Could not scan EICAR test string via socket at {}",
            CLAMD_HOST_SOCKET.socket_path
        );
        let buffer = include_bytes!("data/eicar.txt");
        let response = clamav_client::async_std::scan_buffer(buffer, CLAMD_HOST_SOCKET, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_std_scan_socket_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response =
            clamav_client::async_std::scan_file(CLEAN_TEST_FILE_PATH, CLAMD_HOST_SOCKET, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_std_scan_socket_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response =
            clamav_client::async_std::scan_file(OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_SOCKET, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn async_std_ping_tcp() {
        let err_msg = format!(
            "Could not ping clamd via TCP at {}",
            CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::async_std::ping(CLAMD_HOST_TCP)
            .await
            .expect(&err_msg);
        assert_eq!(&response, clamav_client::PONG);
    }

    #[async_std::test]
    async fn async_std_scan_tcp_infected_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response =
            clamav_client::async_std::scan_file(EICAR_TEST_FILE_PATH, CLAMD_HOST_TCP, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn async_std_scan_tcp_infected_buffer() {
        let err_msg = format!(
            "Could not scan EICAR test string via TCP at {}",
            CLAMD_HOST_TCP.host_address
        );
        let buffer = include_bytes!("data/eicar.txt");
        let response = clamav_client::async_std::scan_buffer(buffer, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn async_std_scan_tcp_clean_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response =
            clamav_client::async_std::scan_file(CLEAN_TEST_FILE_PATH, CLAMD_HOST_TCP, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[async_std::test]
    async fn async_std_scan_tcp_oversized_file() {
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response =
            clamav_client::async_std::scan_file(OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_TCP, None)
                .await
                .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(feature = "async-std")]
mod async_std_stream_tests {
    use super::*;
    use async_std::{fs::File, path::Path};
    use async_std_util::io::ReaderStream;

    const CLAMD_HOST_TCP: clamav_client::async_std::Tcp<&str> = clamav_client::async_std::Tcp {
        host_address: TEST_HOST_ADDRESS,
    };

    #[cfg(unix)]
    const CLAMD_HOST_SOCKET: clamav_client::async_std::Socket<&str> =
        clamav_client::async_std::Socket {
            socket_path: TEST_SOCKET_PATH,
        };

    async fn stream_from_file<P: AsRef<Path>>(path: P) -> ReaderStream<File> {
        let path_str = path.as_ref().to_str().expect("Invalid path");
        let err_msg = format!("Could not read test file {}", path_str);
        let file = File::open(path).await.expect(&err_msg);
        ReaderStream::with_capacity(file, 16)
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_std_scan_socket_infected_stream() {
        let stream = stream_from_file(EICAR_TEST_FILE_PATH).await;
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::async_std::scan_stream(stream, CLAMD_HOST_SOCKET, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_std_scan_socket_clean_stream() {
        let stream = stream_from_file(CLEAN_TEST_FILE_PATH).await;
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::async_std::scan_stream(stream, CLAMD_HOST_SOCKET, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[async_std::test]
    #[cfg(unix)]
    async fn async_std_scan_socket_oversized_stream() {
        let stream = stream_from_file(OVERSIZED_TEST_FILE_PATH).await;
        let err_msg = format!(
            "Could not scan test file {} via socket at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_SOCKET.socket_path
        );
        let response = clamav_client::async_std::scan_stream(stream, CLAMD_HOST_SOCKET, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn async_std_scan_tcp_infected_stream() {
        let stream = stream_from_file(EICAR_TEST_FILE_PATH).await;
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            EICAR_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::async_std::scan_stream(stream, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }

    #[async_std::test]
    async fn async_std_scan_tcp_clean_stream() {
        let stream = stream_from_file(CLEAN_TEST_FILE_PATH).await;
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            CLEAN_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::async_std::scan_stream(stream, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, OK_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(true));
    }

    #[async_std::test]
    async fn async_std_scan_tcp_oversized_stream() {
        let stream = stream_from_file(OVERSIZED_TEST_FILE_PATH).await;
        let err_msg = format!(
            "Could not scan test file {} via TCP at {}",
            OVERSIZED_TEST_FILE_PATH, CLAMD_HOST_TCP.host_address
        );
        let response = clamav_client::async_std::scan_stream(stream, CLAMD_HOST_TCP, None)
            .await
            .expect(&err_msg);
        assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
        assert_eq!(clamav_client::clean(&response), Ok(false));
    }
}

#[cfg(feature = "async-std")]
mod async_std_util;
