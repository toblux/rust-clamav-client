use clamav_client;

#[cfg(unix)]
const TEST_SOCKET_PATH: &str = "/tmp/clamd.socket";
const TEST_HOST_ADDRESS: &str = "localhost:3310";
const EICAR_TEST_FILE_PATH: &str = "tests/eicar.txt";
const CLEAN_TEST_FILE_PATH: &str = "README.md";

const PONG_RESPONSE: &[u8] = b"PONG\0";
const EICAR_FILE_SIGNATURE_FOUND_RESPONSE: &[u8] = b"stream: Eicar-Signature FOUND\0";
const OK_RESPONSE: &[u8] = b"stream: OK\0";

// `StreamMaxLength` is limited to 1 MB in `clamd.conf` - this binary test file
// is exactly 1 byte larger than allowed to test the "size limit exceeded" error
const OVERSIZED_TEST_FILE_PATH: &str = "tests/stream-max-length-test-file.bin";
const SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE: &[u8] = b"INSTREAM size limit exceeded. ERROR\0";

#[test]
#[cfg(unix)]
fn ping_socket() {
    let err_msg = format!(
        "Could not ping clamd via Unix socket at {}",
        TEST_SOCKET_PATH
    );
    let response = clamav_client::ping_socket(TEST_SOCKET_PATH).expect(&err_msg);
    assert_eq!(&response, PONG_RESPONSE);
}

#[tokio::test]
#[cfg(all(unix, feature = "tokio"))]
async fn async_ping_socket() {
    let err_msg = format!(
        "Could not ping clamd via Unix socket at {}",
        TEST_SOCKET_PATH
    );
    let response = clamav_client::tokio::ping_socket(TEST_SOCKET_PATH)
        .await
        .expect(&err_msg);
    assert_eq!(&response, PONG_RESPONSE);
}

#[test]
#[cfg(unix)]
fn scan_socket_infected_file() {
    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        EICAR_TEST_FILE_PATH, TEST_SOCKET_PATH
    );
    let response = clamav_client::scan_file_socket(EICAR_TEST_FILE_PATH, TEST_SOCKET_PATH, None)
        .expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(all(unix, feature = "tokio"))]
async fn async_scan_socket_infected_file() {
    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        EICAR_TEST_FILE_PATH, TEST_SOCKET_PATH
    );
    let response =
        clamav_client::tokio::scan_file_socket(EICAR_TEST_FILE_PATH, TEST_SOCKET_PATH, None)
            .await
            .expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[test]
#[cfg(unix)]
fn scan_socket_infected_buffer() {
    let err_msg = format!(
        "Could not scan EICAR test string via socket at {}",
        TEST_SOCKET_PATH
    );
    let buffer = include_bytes!("eicar.txt");
    let response =
        clamav_client::scan_buffer_socket(buffer, TEST_SOCKET_PATH, None).expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(all(unix, feature = "tokio"))]
async fn async_scan_socket_infected_buffer() {
    let err_msg = format!(
        "Could not scan EICAR test string via socket at {}",
        TEST_SOCKET_PATH
    );
    let buffer = include_bytes!("eicar.txt");
    let response = clamav_client::tokio::scan_buffer_socket(buffer, TEST_SOCKET_PATH, None)
        .await
        .expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(all(feature = "tokio", feature = "tokio-stream"))]
async fn async_scan_socket_infected_stream() {
    use tokio::fs::File;
    use tokio_stream::StreamExt;
    use tokio_util::io::ReaderStream;

    let err_msg = format!("Could not read test file {}", EICAR_TEST_FILE_PATH);
    let file = File::open(EICAR_TEST_FILE_PATH).await.expect(&err_msg);
    let stream = ReaderStream::new(file).map(|res| res.map(|b| b.to_vec()));

    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        EICAR_TEST_FILE_PATH, TEST_SOCKET_PATH
    );
    let response = clamav_client::tokio::scan_stream_socket(stream, TEST_SOCKET_PATH, None)
        .await
        .expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[test]
#[cfg(unix)]
fn scan_socket_clean_file() {
    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        CLEAN_TEST_FILE_PATH, TEST_SOCKET_PATH
    );
    let response = clamav_client::scan_file_socket(CLEAN_TEST_FILE_PATH, TEST_SOCKET_PATH, None)
        .expect(&err_msg);
    assert_eq!(&response, OK_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(true));
}

#[tokio::test]
#[cfg(all(unix, feature = "tokio"))]
async fn async_scan_socket_clean_file() {
    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        CLEAN_TEST_FILE_PATH, TEST_SOCKET_PATH
    );
    let response =
        clamav_client::tokio::scan_file_socket(CLEAN_TEST_FILE_PATH, TEST_SOCKET_PATH, None)
            .await
            .expect(&err_msg);
    assert_eq!(&response, OK_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(true));
}

#[tokio::test]
#[cfg(all(feature = "tokio", feature = "tokio-stream"))]
async fn async_scan_socket_clean_stream() {
    use tokio::fs::File;
    use tokio_stream::StreamExt;
    use tokio_util::io::ReaderStream;

    let err_msg = format!("Could not read test file {}", CLEAN_TEST_FILE_PATH);
    let file = File::open(CLEAN_TEST_FILE_PATH).await.expect(&err_msg);
    let stream = ReaderStream::new(file).map(|res| res.map(|b| b.to_vec()));

    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        CLEAN_TEST_FILE_PATH, TEST_SOCKET_PATH
    );
    let response = clamav_client::tokio::scan_stream_socket(stream, TEST_SOCKET_PATH, None)
        .await
        .expect(&err_msg);
    assert_eq!(&response, OK_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(true));
}

#[test]
#[cfg(unix)]
fn scan_socket_oversized_file() {
    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        OVERSIZED_TEST_FILE_PATH, TEST_SOCKET_PATH
    );
    let response =
        clamav_client::scan_file_socket(OVERSIZED_TEST_FILE_PATH, TEST_SOCKET_PATH, None)
            .expect(&err_msg);
    assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(all(unix, feature = "tokio"))]
async fn async_scan_socket_oversized_file() {
    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        OVERSIZED_TEST_FILE_PATH, TEST_SOCKET_PATH
    );
    let response =
        clamav_client::tokio::scan_file_socket(OVERSIZED_TEST_FILE_PATH, TEST_SOCKET_PATH, None)
            .await
            .expect(&err_msg);
    assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(all(feature = "tokio", feature = "tokio-stream"))]
async fn async_scan_socket_oversized_stream() {
    use tokio::fs::File;
    use tokio_stream::StreamExt;
    use tokio_util::io::ReaderStream;

    let err_msg = format!("Could not read test file {}", OVERSIZED_TEST_FILE_PATH);
    let file = File::open(OVERSIZED_TEST_FILE_PATH).await.expect(&err_msg);
    let stream = ReaderStream::new(file).map(|res| res.map(|b| b.to_vec()));

    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        OVERSIZED_TEST_FILE_PATH, TEST_SOCKET_PATH
    );
    let response = clamav_client::tokio::scan_stream_socket(stream, TEST_SOCKET_PATH, None)
        .await
        .expect(&err_msg);
    assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[test]
fn ping_tcp() {
    let err_msg = format!("Could not ping clamd via TCP at {}", TEST_HOST_ADDRESS);
    let response = clamav_client::ping_tcp(TEST_HOST_ADDRESS).expect(&err_msg);
    assert_eq!(&response, PONG_RESPONSE);
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn async_ping_tcp() {
    let err_msg = format!("Could not ping clamd via TCP at {}", TEST_HOST_ADDRESS);
    let response = clamav_client::tokio::ping_tcp(TEST_HOST_ADDRESS)
        .await
        .expect(&err_msg);
    assert_eq!(&response, PONG_RESPONSE);
}

#[test]
fn scan_tcp_infected_file() {
    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        EICAR_TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response = clamav_client::scan_file_tcp(EICAR_TEST_FILE_PATH, TEST_HOST_ADDRESS, None)
        .expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn async_scan_tcp_infected_file() {
    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        EICAR_TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response =
        clamav_client::tokio::scan_file_tcp(EICAR_TEST_FILE_PATH, TEST_HOST_ADDRESS, None)
            .await
            .expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[test]
fn scan_tcp_infected_buffer() {
    let err_msg = format!(
        "Could not scan EICAR test string via TCP at {}",
        TEST_HOST_ADDRESS
    );
    let buffer = include_bytes!("eicar.txt");
    let response = clamav_client::scan_buffer_tcp(buffer, TEST_HOST_ADDRESS, None).expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn async_scan_tcp_infected_buffer() {
    let err_msg = format!(
        "Could not scan EICAR test string via TCP at {}",
        TEST_HOST_ADDRESS
    );
    let buffer = include_bytes!("eicar.txt");
    let response = clamav_client::tokio::scan_buffer_tcp(buffer, TEST_HOST_ADDRESS, None)
        .await
        .expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(all(feature = "tokio", feature = "tokio-stream"))]
async fn async_scan_tcp_infected_stream() {
    use tokio::fs::File;
    use tokio_stream::StreamExt;
    use tokio_util::io::ReaderStream;

    let err_msg = format!("Could not read test file {}", EICAR_TEST_FILE_PATH);
    let file = File::open(EICAR_TEST_FILE_PATH).await.expect(&err_msg);
    let stream = ReaderStream::new(file).map(|res| res.map(|b| b.to_vec()));

    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        EICAR_TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response = clamav_client::tokio::scan_stream_tcp(stream, TEST_HOST_ADDRESS, None)
        .await
        .expect(&err_msg);
    assert_eq!(&response, EICAR_FILE_SIGNATURE_FOUND_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[test]
fn scan_tcp_clean_file() {
    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        CLEAN_TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response = clamav_client::scan_file_tcp(CLEAN_TEST_FILE_PATH, TEST_HOST_ADDRESS, None)
        .expect(&err_msg);
    assert_eq!(&response, OK_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(true));
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn async_scan_tcp_clean_file() {
    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        CLEAN_TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response =
        clamav_client::tokio::scan_file_tcp(CLEAN_TEST_FILE_PATH, TEST_HOST_ADDRESS, None)
            .await
            .expect(&err_msg);
    assert_eq!(&response, OK_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(true));
}

#[tokio::test]
#[cfg(all(feature = "tokio", feature = "tokio-stream"))]
async fn async_scan_tcp_clean_stream() {
    use tokio::fs::File;
    use tokio_stream::StreamExt;
    use tokio_util::io::ReaderStream;

    let err_msg = format!("Could not read test file {}", CLEAN_TEST_FILE_PATH);
    let file = File::open(CLEAN_TEST_FILE_PATH).await.expect(&err_msg);
    let stream = ReaderStream::new(file).map(|res| res.map(|b| b.to_vec()));

    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        CLEAN_TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response = clamav_client::tokio::scan_stream_tcp(stream, TEST_HOST_ADDRESS, None)
        .await
        .expect(&err_msg);
    assert_eq!(&response, OK_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(true));
}

#[test]
fn scan_tcp_oversized_file() {
    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        OVERSIZED_TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response = clamav_client::scan_file_tcp(OVERSIZED_TEST_FILE_PATH, TEST_HOST_ADDRESS, None)
        .expect(&err_msg);
    assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn async_scan_tcp_oversized_file() {
    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        OVERSIZED_TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response =
        clamav_client::tokio::scan_file_tcp(OVERSIZED_TEST_FILE_PATH, TEST_HOST_ADDRESS, None)
            .await
            .expect(&err_msg);
    assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}

#[tokio::test]
#[cfg(all(feature = "tokio", feature = "tokio-stream"))]
async fn async_scan_tcp_oversized_stream() {
    use tokio::fs::File;
    use tokio_stream::StreamExt;
    use tokio_util::io::ReaderStream;

    let err_msg = format!("Could not read test file {}", OVERSIZED_TEST_FILE_PATH);
    let file = File::open(OVERSIZED_TEST_FILE_PATH).await.expect(&err_msg);
    let stream = ReaderStream::new(file).map(|res| res.map(|b| b.to_vec()));

    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        OVERSIZED_TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response = clamav_client::tokio::scan_stream_tcp(stream, TEST_HOST_ADDRESS, None)
        .await
        .expect(&err_msg);
    assert_eq!(&response, SIZE_LIMIT_EXCEEDED_ERROR_RESPONSE);
    assert_eq!(clamav_client::clean(&response), Ok(false));
}
