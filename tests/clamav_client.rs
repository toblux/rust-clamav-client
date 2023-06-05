use clamav_client::*;

#[cfg(target_family = "unix")]
const TEST_SOCKET_PATH: &str = "/tmp/clamd.socket";
const TEST_HOST_ADDRESS: &str = "localhost:3310";
const TEST_FILE_PATH: &str = "tests/eicar.txt";

const PONG_RESPONSE: &[u8] = b"PONG\0";
const EICAR_FOUND_RESPONSE: &[u8] = b"stream: Eicar-Signature FOUND\0";
const EICAR_BUFFER_FOUND_RESPONSE: &[u8] = b"stream: Win.Test.EICAR_HDB-1 FOUND\0";

#[test]
#[cfg(target_family = "unix")]
fn test_ping_socket() {
    let err_msg = format!(
        "Could not ping clamd via Unix socket at {}",
        TEST_SOCKET_PATH
    );
    let response = ping_socket(TEST_SOCKET_PATH).expect(&err_msg);
    assert_eq!(&response, PONG_RESPONSE);
}

#[test]
fn test_ping_tcp() {
    let err_msg = format!("Could not ping clamd via TCP at {}", TEST_HOST_ADDRESS);
    let response = ping_tcp(TEST_HOST_ADDRESS).expect(&err_msg);
    assert_eq!(&response, PONG_RESPONSE);
}

#[test]
#[cfg(target_family = "unix")]
fn test_scan_socket() {
    let err_msg = format!(
        "Could not scan test file {} via socket at {}",
        TEST_FILE_PATH, TEST_SOCKET_PATH
    );

    let response = scan_socket(TEST_FILE_PATH, TEST_SOCKET_PATH, None).expect(&err_msg);
    assert_eq!(&response, EICAR_FOUND_RESPONSE);

    let is_clean = clean(&response);
    assert_eq!(is_clean, Ok(false));
}

#[test]
fn test_scan_tcp() {
    let err_msg = format!(
        "Could not scan test file {} via TCP at {}",
        TEST_FILE_PATH, TEST_HOST_ADDRESS
    );
    let response = scan_tcp(TEST_FILE_PATH, TEST_HOST_ADDRESS, None).expect(&err_msg);
    assert_eq!(&response, EICAR_FOUND_RESPONSE);

    let is_clean = clean(&response);
    assert_eq!(is_clean, Ok(false));
}

#[test]
fn test_scan_buffer_tcp() {
    let err_msg = format!(
        "Could not scan EICAR string via TCP at {}",
        TEST_HOST_ADDRESS
    );

    let buffer = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        .bytes()
        .collect::<Vec<u8>>();

    let response = scan_buffer_tcp(&buffer, TEST_HOST_ADDRESS, None).expect(&err_msg);
    assert_eq!(&response, EICAR_BUFFER_FOUND_RESPONSE);

    let is_clean = clean(&response);
    assert_eq!(is_clean, Ok(false));
}
