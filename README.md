# Rust ClamAV Client

A simple ClamAV client to stream files or in-memory data to [clamd](https://linux.die.net/man/8/clamd) for antivirus scanning.

Please note: The functions `ping_socket`, `scan_file_socket`, and `scan_buffer_socket` are only available on Unix platforms.

![Workflow status](https://github.com/toblux/rust-clamav-client/actions/workflows/test.yml/badge.svg)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
clamav-client = "0.3.2"
```

To use the `async` functions in `clamav_client::tokio`, add this to your `Cargo.toml`:

```toml
[dependencies]
clamav-client = { version = "0.3.2", features = ["tokio"] }
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
let scan_file_response = clamav_client::scan_file_tcp(file_path, clamd_host_address, None).unwrap();
let file_clean = clamav_client::clean(&scan_file_response).unwrap();
if file_clean {
    println!("No virus found in {}", file_path);
} else {
    println!("The file {} is infected!", file_path);
}

// Scan in-memory data for viruses
let buffer = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
let scan_buffer_response = clamav_client::scan_buffer_tcp(buffer, clamd_host_address, None).unwrap();
let data_clean = clamav_client::clean(&scan_buffer_response).unwrap();
if data_clean {
    println!("No virus found");
} else {
    println!("The data is infected!");
}
```

## Usage - Async with Tokio

```rust
#[cfg(feature = "tokio")]
async fn tokio_example() {
    let clamd_host_address = "localhost:3310";

    // Ping clamd asynchronously and await the result
    let clamd_available = match clamav_client::tokio::ping_tcp(clamd_host_address).await {
        Ok(ping_response) => ping_response == b"PONG\0",
        Err(_) => false,
    };

    if !clamd_available {
        println!("Cannot ping clamd at {}", clamd_host_address);
        return;
    }

    let file_path = "tests/eicar.txt";
    let buffer = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;

    // Concurrently scan a file and a data buffer for viruses
    let (scan_file_result, scan_buffer_result) = tokio::join!(
        clamav_client::tokio::scan_file_tcp(file_path, clamd_host_address, None),
        clamav_client::tokio::scan_buffer_tcp(buffer, clamd_host_address, None)
    );

    let scan_file_response = scan_file_result.unwrap();
    let file_clean = clamav_client::clean(&scan_file_response).unwrap();
    if file_clean {
        println!("No virus found in {}", file_path);
    } else {
        println!("The file {} is infected!", file_path);
    }

    let scan_buffer_response = scan_buffer_result.unwrap();
    let data_clean = clamav_client::clean(&scan_buffer_response).unwrap();
    if data_clean {
        println!("No virus found");
    } else {
        println!("The data is infected!");
    }
}
```

## Contributors

- [Christopher Prohm](https://github.com/chmp)
- [Paul Makles](https://github.com/insertish)
- [Sean Clarke](https://github.com/SeanEClarke)
- [Kanji Tanaka](https://github.com/kaicoh)
