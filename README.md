# Rust ClamAV Client

A simple ClamAV client to stream files to [clamd](https://linux.die.net/man/8/clamd) for antivirus scanning.

Please note: The functions `ping_socket` and `scan_socket` are only available on Unix platforms.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
clamav-client = "0.1.3"
```

## Usage

Ensure ClamD is running by pinging the server for a response:

```rust
let clamd_host_address = "localhost:3310";

let clamd_available = match clamav_client::ping_tcp(clamd_host_address) {
    Ok(ping_response) => ping_response == b"PONG\0",
    Err(_) => false,
};

if !clamd_available {
    println!("Cannot ping clamd at {}", clamd_host_address);
    return;
}
```

Scan a file for detections:

```rust
let file_path = "virus.txt";
let scan_response = clamav_client::scan_tcp(file_path, clamd_host_address, None).unwrap();
let file_clean = clamav_client::clean(&scan_response).unwrap();
if file_clean {
    println!("No virus found in {}", file_path);
} else {
    println!("The file {} is infected!", file_path);
}
```

Scan a buffer from memory:

```rust
let buffer = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    .bytes()
    .collect::<Vec<u8>>();

let scan_response = clamav_client::scan_buffer_tcp(buffer, clamd_host_address, None).unwrap();
let file_clean = clamav_client::clean(&scan_response).unwrap();
assert!(!file_clean);
```
