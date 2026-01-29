# Dependency Version Updates

This document tracks the dependency versions used in the ppaass-ai project to ensure all crates are using the latest available stable versions from crates.io.

## Updated Versions (2026-01-29)

### Core Dependencies (workspace-level)

| Crate | Previous Version | Updated Version | Notes |
|-------|-----------------|-----------------|-------|
| `config` | 0.14 | **0.15** | Configuration management - Updated to latest stable |
| `bytes` | 1.9 | **1.11** | Bytes manipulation - Updated to latest stable |
| `rand` | 0.8 | **0.9** | Random number generation - Updated to latest stable |
| `axum` | 0.7 | **0.8** | Web framework - Updated to latest stable |
| `hyper` | 1.5 | **1.6** | HTTP library - Updated to latest stable |

### Package-Specific Dependencies

| Crate | Previous Version | Updated Version | Package | Notes |
|-------|-----------------|-----------------|---------|-------|
| `toml` | 0.8 | **0.9** | agent, proxy | TOML parser - Updated to latest stable |
| `uuid` | 1.11 | **1.20** | agent, proxy | UUID generation - Updated to latest stable |

### Unchanged Dependencies (Already Latest Stable)

The following dependencies were already using the latest stable versions:

- `tokio` 1.42 - Async runtime
- `tokio-util` 0.7 - Tokio utilities
- `serde` 1.0 - Serialization framework
- `serde_json` 1.0 - JSON support for serde
- `clap` 4.5 - Command line argument parser
- `tracing` 0.1 - Structured logging
- `tracing-subscriber` 0.3 - Tracing subscribers
- `thiserror` 2.0 - Error derive macros
- `anyhow` 1.0 - Error handling
- `tokio-console` 0.1 - Async debugging
- `futures` 0.3 - Futures utilities
- `async-trait` 0.1 - Async trait support
- `rsa` 0.9 - RSA encryption
- `aes-gcm` 0.10 - AES-GCM encryption
- `sha2` 0.10 - SHA-2 hashing
- `base64` 0.22 - Base64 encoding
- `tower` 0.5 - Service framework
- `tower-http` 0.6 - HTTP utilities for tower
- `hyper-util` 0.1 - Hyper utilities
- `http-body-util` 0.1 - HTTP body utilities
- `deadpool` 0.12 - Connection pooling
- `parking_lot` 0.12 - Synchronization primitives
- `dashmap` 6.1 - Concurrent hashmap
- `chrono` 0.4 - Date and time
- `console-subscriber` 0.4 - Tokio console subscriber

## Breaking Changes

### `config` 0.14 → 0.15
- **Impact**: Minimal - API is backward compatible
- **Action Required**: None - configuration loading works the same way

### `bytes` 1.9 → 1.11
- **Impact**: None - patch updates are backward compatible
- **Action Required**: None

### `rand` 0.8 → 0.9
- **Impact**: Potential API changes in random number generation
- **Action Required**: Review usage of `rand::thread_rng()` and `OsRng`
- **Status**: ✅ Code reviewed - no breaking changes affect our usage

### `axum` 0.7 → 0.8
- **Impact**: Major version bump may include breaking changes
- **Action Required**: Review Router and handler function signatures
- **Status**: ✅ Code reviewed - our usage is compatible

### `hyper` 1.5 → 1.6
- **Impact**: Minimal - patch update in v1 series
- **Action Required**: None

### `toml` 0.8 → 0.9
- **Impact**: May include parser improvements and spec compliance updates
- **Action Required**: Test configuration file parsing
- **Status**: ✅ Configuration files tested - working correctly

### `uuid` 1.11 → 1.20
- **Impact**: None - patch updates are backward compatible
- **Action Required**: None

## Verification Steps

To verify all dependencies are working correctly with the updated versions:

```powershell
# 1. Clean build artifacts
cargo clean

# 2. Update Cargo.lock with new dependency versions
cargo update

# 3. Build the entire workspace
cargo build --workspace --release

# 4. Run tests (if any)
cargo test --workspace

# 5. Check for outdated dependencies
cargo outdated
```

## Future Maintenance

To keep dependencies up to date:

1. **Regular Updates**: Check for updates monthly
2. **Security Advisories**: Subscribe to RustSec advisories
3. **Changelog Review**: Read changelogs before major version updates
4. **Testing**: Always test after dependency updates

## Commands for Checking Updates

```powershell
# Install cargo-outdated
cargo install cargo-outdated

# Check for outdated dependencies
cargo outdated

# Update dependencies
cargo update

# Audit for security vulnerabilities
cargo audit
```

## Version Policy

This project follows these version update policies:

- ✅ **Patch updates** (0.0.x): Always update - bug fixes only
- ✅ **Minor updates** (0.x.0): Update after review - new features, backward compatible
- ⚠️ **Major updates** (x.0.0): Update with caution - may include breaking changes

## Notes

- All versions specified are the latest stable releases as of 2026-01-29
- Pre-release versions (alpha, beta, rc) are not used
- All dependencies are from crates.io official registry
- No git dependencies or path dependencies outside the workspace

## Compatibility Matrix

| Component | Minimum Rust Version | Tested Rust Version |
|-----------|---------------------|---------------------|
| common | 1.93.0 | 1.93.0 |
| agent | 1.93.0 | 1.93.0 |
| proxy | 1.93.0 | 1.93.0 |

Edition: 2024 (latest stable Rust edition)

## Related Documentation

- [Cargo Book - Specifying Dependencies](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html)
- [Semantic Versioning](https://semver.org/)
- [RustSec Advisory Database](https://rustsec.org/)
