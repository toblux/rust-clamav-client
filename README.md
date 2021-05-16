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

```rust
let clamd_host_address = "localhost:3310";

// Ping clamd to make sure the server is available and accepting TCP connections
let clamd_available = match clamav_client::ping_tcp(clamd_host_address) {
    Ok(ping_response) => ping_response == b"PONG\0",
    Err(_) => false,
};

if !clamd_available {
    println!("Cannot ping clamd at {}", clamd_host_address);
    return;
}

// Scan file for viruses
let file_path = "virus.txt";
let scan_response = clamav_client::scan_tcp(file_path, clamd_host_address, None).unwrap();
let file_clean = clamav_client::clean(&scan_response).unwrap();
if file_clean {
    println!("No virus found in {}", file_path);
} else {
    println!("The file {} is infected!", file_path);
}
```
