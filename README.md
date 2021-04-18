# Rust ClamAV Client

Examples of how to use this ClamAV client library can be found [in the tests](tests/clamav_client.rs).

Please note:
- The functions `ping_socket` and `scan_socket` are only available on UNIX platforms.
- The tests only pass if [clamd](https://linux.die.net/man/8/clamd) is running on localhost and accepting TCP connections on port 3310.
