# trust-dns [![Build Status](https://travis-ci.org/bluejekyll/trust-dns.svg?branch=master)](https://travis-ci.org/bluejekyll/trust-dns)
A Rust based DNS client and server, built to be safe and secure from the
ground up.

# Goals

- Build a safe and secure DNS server and client with modern features.
- No panics, all code is guarded
- Use only safe Rust, and avoid all panics with proper Error handling
- Use only stable Rust
- Protect against DDOS attacks (to a degree)
- Support options for Global Load Balancing functions
- Make it dead simple to operate

# Status:

WARNING!!! Under active development!

The client now supports timeouts (thanks mio!). Currently hardcoded to 5 seconds,
 I'll make this configurable if people ask for that, but this allows me to move on.

The server code is complete, the daemon currently only supports IPv4. Master file
parsing is complete and supported.

## RFC's implemented

- [RFC 1035](https://tools.ietf.org/html/rfc1035): Base DNS spec (partial, caching not yet supported)
- [RFC 3596](https://tools.ietf.org/html/rfc3596): IPv6
- [RFC 2136](https://tools.ietf.org/html/rfc2136): Dynamic Update

## RFC's in progress or not yet implemented

- [RFC 1995](https://tools.ietf.org/html/rfc1995): Incremental Zone Transfer
- [RFC 1996](https://tools.ietf.org/html/rfc1996): Notify slaves of update
- [RFC 2782](https://tools.ietf.org/html/rfc2782): Service location
- [RFC 3007](https://tools.ietf.org/html/rfc3007): Secure Dynamic Update
- [RFC 6891](https://tools.ietf.org/html/rfc6891): Extension Mechanisms for DNS
- [RFC 4034](https://tools.ietf.org/html/rfc4034): DNSSEC Resource Records
- [DNSCrypt](https://dnscrypt.org): Trusted DNS queries
- [Update Leases](https://tools.ietf.org/html/draft-sekar-dns-ul-01): Dynamic DNS Update Leases
- [Long-Lived Queries](http://tools.ietf.org/html/draft-sekar-dns-llq-01): Notify with bells

# Usage

This assumes that you have [Rust](https://www.rust-lang.org) stable installed. These
presume that the trust-dns repos have already been synced to the local system:
> $ git clone https://github.com/bluejekyll/trust-dns.git
> $ cd trust-dns

## Testing

-   Unit tests

    These are good for running on local systems. They will create sockets for
    local tests, but will not attempt to access remote systems.
    > $ cargo test

-   Functional tests

    These will try to use some local system tools for compatibility testing,
    and also make some remote requests to verify compatibility with other DNS
    systems. These can not currently be run on Travis for example.
    > $ cargo test --features=ftest

-   Benchmarks

    Waiting on benchmarks to stabilize in mainline Rust.

## Building

-   Production build
    > $ cargo build --release

## Running

Warning: Trust-DNS is still under development, running in production is not
recommended. The server is currently only single-threaded, it is non-blocking
so this should allow it to work with most internal loads.

-   Verify the version
    > $ target/release/named --version

-   Get help
    > $ target/release/named --help

# FAQ

- Why are you building another DNS server?

Because I've gotten tired of seeing the security advisories out there for BIND.
Using Rust semantics it should be possible to develop a high performance and
safe DNS Server that is more resilient to attacks.
