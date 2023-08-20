# Rust ClamAV Client

A simple ClamAV client to stream files or in-memory data to [clamd](https://linux.die.net/man/8/clamd) for antivirus scanning.

Please note: The functions `ping_socket`, `scan_file_socket`, and `scan_buffer_socket` are only available on Unix platforms.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
clamav-client = "0.2.1"
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
let file_path = "tests/eicar.txt";
let scan_file_response =
    clamav_client::scan_file_tcp(file_path, clamd_host_address, None).unwrap();
let file_clean = clamav_client::clean(&scan_file_response).unwrap();
if file_clean {
    println!("No virus found in {}", file_path);
} else {
    println!("The file {} is infected!", file_path);
}

// Scan in-memory data for viruses
let buffer = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
let scan_buffer_response =
    clamav_client::scan_buffer_tcp(buffer, clamd_host_address, None).unwrap();
let data_clean = clamav_client::clean(&scan_buffer_response).unwrap();
if data_clean {
    println!("No virus found");
} else {
    println!("The data is infected!");
}
```

## Contributors

- [Christopher Prohm](https://github.com/chmp)
- [Paul Makles](https://github.com/insertish)
