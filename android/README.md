# Android Agent

This directory contains an Android VPN agent for PPAASS.

The Android app owns the platform VPN layer:

- `PpaassVpnService` requests and establishes Android `VpnService`.
- The service excludes the app package from the VPN so agent-to-proxy control sockets do not loop into the TUN.
- The raw VPN file descriptor is detached and passed to the Rust JNI library.

The Rust library owns the packet and protocol layer:

- `android/native` wraps the VPN fd with `AsyncFd`.
- `netstack-smoltcp` turns IP packets into TCP streams and UDP payload sessions.
- TCP and UDP flows are forwarded to the existing PPAASS proxy protocol through the `common` and `protocol` crates.
- Android's app allow-list decides which applications enter the VPN.
- DNS is always routed through the VPN; Rust maps TCP/UDP port 53 packets to the proxy-side DNS path, matching the desktop agent TUN mode.
- QUIC blocking mirrors the desktop agent TUN mode behavior.

## Build

Install Android Studio or an Android SDK, then install the Rust Android targets and `cargo-ndk`:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install cargo-ndk
```

Build from this directory with a local Gradle install, or open this directory in Android Studio:

```bash
gradle assembleDebug
```

The Gradle build runs:

```bash
cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -o app/src/main/jniLibs build --manifest-path native/Cargo.toml --release
```

Use `-PskipRustBuild=true` only when prebuilt `.so` files already exist under `app/src/main/jniLibs`.

The Android app layer is plain Java. Rust remains in `android/native` for the packet stack and proxy protocol bridge.

## Runtime Config

Open the app, fill in:

- proxy endpoints, comma or newline separated; the default is `140.82.30.214:80`
- username, defaulting to `user1`
- RSA private key PEM, defaulting to the private key paired with `config/local/users.toml` `users.user1.public_key_pem`
- TUN IPv4 CIDR, default `10.10.10.2/24`
- TUN IPv6 CIDR, default empty. Keep IPv6 disabled unless the proxy path is known to support IPv6 egress.
- applications that should use the VPN

Android is pointed at a routed DNS address inside the VPN network path; Rust maps UDP port 53 packets to `ProxyDns`, so the proxy machine selects the upstream DNS from its system configuration. QUIC is blocked by default to match the desktop TUN mode and make Google Play / YouTube fall back to TCP/TLS on proxy paths that do not handle UDP/443 reliably.
