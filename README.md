# Rust ClamAV Client

A simple ClamAV client to send files, in-memory data, and data streams to `clamd` for antivirus scanning.

It provides a synchronous API and asynchronous functions for both Tokio and async-std.

Check out the [examples](#examples) below, the [integration tests](tests/clamav_client.rs), or the [API docs](https://docs.rs/clamav-client) for more information on how to use this library.

[![Build status](https://github.com/toblux/rust-clamav-client/actions/workflows/test.yml/badge.svg)](https://github.com/toblux/rust-clamav-client/actions)
[![Crates.io](https://img.shields.io/crates/v/clamav-client.svg)](https://crates.io/crates/clamav-client)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
clamav-client = "1.0.1"
```

To use the `async` functions in `clamav_client::tokio`, add this to your `Cargo.toml`:

```toml
[dependencies]
clamav-client = { version = "1.0.1", features = ["tokio"] }
```

To scan Tokio streams, enable the `tokio-stream` feature instead and add this to your `Cargo.toml`:

```toml
[dependencies]
clamav-client = { version = "1.0.1", features = ["tokio-stream"] }
```

Support for `async-std` is also available by enabling the `async-std` feature:

```toml
[dependencies]
clamav-client = { version = "1.0.1", features = ["async-std"] }
```

## Migrations

### Migrate to 1.x

The `*_socket` and `*_tcp` functions were deprecated in version 0.5.0 and have been removed in version 1.0.0.

### Migrate to 0.5.x

The `*_socket` and `*_tcp` functions have been deprecated in favor of more general functions with the same name, but without the suffixes. These updated functions, such as `ping`, `scan_buffer`, and `scan_file`, now have the connection type (TCP or Unix socket) as a parameter, effectively replacing the `host_address` and `socket_path` parameters.

For example,

```rust,ignore
let clamd_host_address = "localhost:3310";
let result = clamav_client::scan_file_tcp("README.md", clamd_host_address, None);
assert!(result.is_ok());
```

becomes:

```rust
let clamd_tcp = clamav_client::Tcp{ host_address: "localhost:3310" };
let result = clamav_client::scan_file("README.md", clamd_tcp, None);
assert!(result.is_ok());
```

## Examples

### Usage

```rust
let clamd_tcp = clamav_client::Tcp{ host_address: "localhost:3310" };

// Ping clamd to make sure the server is available and accepting TCP connections
let clamd_available = match clamav_client::ping(clamd_tcp) {
    Ok(ping_response) => ping_response == clamav_client::PONG,
    Err(_) => false,
};

if !clamd_available {
    println!("Cannot ping clamd at {}", clamd_tcp.host_address);
    return;
}
assert!(clamd_available);

// Scan file for viruses
let file_path = "tests/data/eicar.txt";
let scan_file_response = clamav_client::scan_file(file_path, clamd_tcp, None).unwrap();
let file_clean = clamav_client::clean(&scan_file_response).unwrap();
if file_clean {
    println!("No virus found in {}", file_path);
} else {
    println!("The file {} is infected!", file_path);
}
assert!(!file_clean);

// Scan in-memory data for viruses
let buffer = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
let scan_buffer_response = clamav_client::scan_buffer(buffer, clamd_tcp, None).unwrap();
let data_clean = clamav_client::clean(&scan_buffer_response).unwrap();
if data_clean {
    println!("No virus found");
} else {
    println!("The data is infected!");
}
assert!(!data_clean);
```

### Usage - Async with `tokio`

```rust
#[cfg(feature = "tokio-stream")]
tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
    let clamd_tcp = clamav_client::tokio::Tcp{ host_address: "localhost:3310" };

    // Ping clamd asynchronously and await the result
    let clamd_available = match clamav_client::tokio::ping(clamd_tcp).await {
        Ok(ping_response) => ping_response == clamav_client::PONG,
        Err(_) => false,
    };

    if !clamd_available {
        println!("Cannot ping clamd at {}", clamd_tcp.host_address);
        return;
    }
    assert!(clamd_available);

    let file_path = "tests/data/eicar.txt";
    let buffer = br#"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"#;
    let file = tokio::fs::File::open(file_path).await.unwrap();
    let stream = tokio_util::io::ReaderStream::new(file);

    // Concurrently scan a file, a data buffer, and a file stream for viruses
    let (scan_file_result, scan_buffer_result, scan_stream_result) = tokio::join!(
        clamav_client::tokio::scan_file(file_path, clamd_tcp, None),
        clamav_client::tokio::scan_buffer(buffer, clamd_tcp, None),
        clamav_client::tokio::scan_stream(stream, clamd_tcp, None)
    );

    let scan_file_response = scan_file_result.unwrap();
    let file_clean = clamav_client::clean(&scan_file_response).unwrap();
    if file_clean {
        println!("No virus found in {}", file_path);
    } else {
        println!("The file {} is infected!", file_path);
    }
    assert!(!file_clean);

    let scan_buffer_response = scan_buffer_result.unwrap();
    let data_clean = clamav_client::clean(&scan_buffer_response).unwrap();
    if data_clean {
        println!("No virus found");
    } else {
        println!("The data buffer is infected!");
    }
    assert!(!data_clean);

    let scan_stream_response = scan_stream_result.unwrap();
    let stream_clean = clamav_client::clean(&scan_stream_response).unwrap();
    if stream_clean {
        println!("No virus found");
    } else {
        println!("The file stream is infected!");
    }
    assert!(!stream_clean);
})
```

### Usage - Async with `async-std`

```rust
#[cfg(feature = "async-std")]
async_std::task::block_on(async {
    let clamd_tcp = clamav_client::async_std::Tcp{ host_address: "localhost:3310" };

    // Ping clamd asynchronously and await the result
    let clamd_available = match clamav_client::async_std::ping(clamd_tcp).await {
        Ok(ping_response) => ping_response == clamav_client::PONG,
        Err(_) => false,
    };

    if !clamd_available {
        println!("Cannot ping clamd at {}", clamd_tcp.host_address);
        return;
    }
    assert!(clamd_available);

    // Scan a file for viruses
    let file_path = "tests/data/eicar.txt";
    let scan_file_result = clamav_client::async_std::scan_file(file_path, clamd_tcp, None).await;
    let scan_file_response = scan_file_result.unwrap();
    let file_clean = clamav_client::clean(&scan_file_response).unwrap();
    if file_clean {
        println!("No virus found in {}", file_path);
    } else {
        println!("The file {} is infected!", file_path);
    }
    assert!(!file_clean);
})
```

More examples can be found in the [tests](tests/clamav_client.rs).

## Links

- [API documentation on docs.rs](https://docs.rs/clamav-client)
- [clamav-client on crates.io](https://crates.io/crates/clamav-client/)

## Development
### Testing locally

For the tests to pass, you should start `clamd` as follows:

`clamd -F --config-file=clamd/clamd.conf`

and then run `cargo test --all-features` to cover all tests.

It doesn't really matter how you start `clamd`, as long as the options from [clamd.conf](clamd/clamd.conf) are the same for your configuration.

## Contributing

Contributions are welcome!

## Contributors

- [Christopher Prohm](https://github.com/chmp)
- [Paul Makles](https://github.com/insertish)
- [Sean Clarke](https://github.com/SeanEClarke)
- [Kanji Tanaka](https://github.com/kaicoh)
