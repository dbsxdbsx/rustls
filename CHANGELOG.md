# Changelog

## [0.23.33] - 2025-09-21

### Added
- **HelloPolicy Framework**: Introduced `HelloPolicy` trait for customizable ClientHello construction
  - `DefaultHelloPolicy`: Maintains byte-identical behavior with upstream Rustls
  - `BrowserLikePolicy`: Provides browser fingerprint presets
  - `ChromeLatest` preset: Mimics Chrome browser ClientHello characteristics
- **ClientConfig Integration**: Added `with_hello_policy()` and `set_hello_policy()` methods
- **ALPN Control**: Policy-based ALPN protocol ordering and override capabilities
- **Cipher Suite Ordering**: Customizable TLS 1.3 cipher suite preferences
- **Extension Ordering**: Deterministic extension ordering via configurable seed
- **Comprehensive Testing**: Added `hello_policy_chrome_latest_applies()` test suite

### Technical Details
- New module: `rustls::client::hello_policy`
- Zero-overhead when no policy is configured (maintains upstream compatibility)
- TLS 1.3 focused implementation (TLS 1.2 remains unchanged)
- Full backward compatibility with existing Rustls ecosystem

### Notes
- Windows users with `aws-lc-rs` provider can use `AWS_LC_SYS_PREBUILT_NASM=1` to avoid NASM installation
- All existing tests pass (139/139) ensuring no regression in default behavior

The detailed list of upstream changes can be found at
https://github.com/rustls/rustls/releases.
