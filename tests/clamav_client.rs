use clamav_client;

#[cfg(target_family = "unix")]
const TEST_SOCKET_PATH: &str = "/tmp/clamd.socket";
const TEST_HOST_ADDRESS: &str = "localhost:3310";
const EICAR_TEST_FILE_PATH: &str = "tests/eicar.txt";
const CLEAN_TEST_FILE_PATH: &str = "README.md";

const PONG_RESPONSE: &[u8] = b"PONG\0";
const EICAR_FILE_SIGNATURE_FOUND_RESPONSE: &[u8] = b"stream: Eicar-Signature FOUND\0";
const OK_RESPONSE: &[u8] = b"stream: OK\0";

#[test]
#[cfg(target_family = "unix")]
fn ping_socket() {
    let err_msg = format!(
        "Could not ping clamd via Unix socket at {}",
        TEST_SOCKET_PATH
    );
    let response = clamav_client::ping_socket(TEST_SOCKET_PATH).expect(&err_msg);
    assert_eq!(&response, PONG_RESPONSE);
}

#[test]
fn ping_tcp() {
    let err_msg = format!("Could not ping clamd via TCP at {}", TEST_HOST_ADDRESS);
    let response = clamav_client::ping_tcp(TEST_HOST_ADDRESS).expect(&err_msg);
    assert_eq!(&response, PONG_RESPONSE);
}

#[test]
#[cfg(target_family = "unix")]
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

#[test]
#[cfg(target_family = "unix")]
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

#[test]
#[cfg(target_family = "unix")]
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
