# Rust ClamAV Client

Please note:

- The functions `ping_socket` and `scan_socket` are only available on Unix platforms.
- The default [clamd](https://linux.die.net/man/8/clamd) configuration usually rejects TCP connections for security reasons. Please enable TCP in your ClamAV daemon if you want to use the functions `ping_tcp` and `scan_tcp`.

## Usage

```rust
fn main() {
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
}
```
