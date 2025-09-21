# Changelog

## [0.23.31] - 2025-09-21

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


### Changed
- Client API: `ClientConfig` builder method `with_no_client_auth()` now returns `ClientConfig` (non-`Result`) for better ecosystem compatibility (e.g. `hickory-proto`). Updated all in-repo usages (examples/benches/docs) to remove `?`/`.unwrap()` accordingly.
- Examples/benches: aligned code to new signature; `cargo check` passes across the workspace.
- Minor: removed trivial `Vec<u8>` casts in GREASE extension value construction to satisfy clippy.

### Notes
- Windows users with `aws-lc-rs` provider can use `AWS_LC_SYS_PREBUILT_NASM=1` to avoid NASM installation
- All existing tests pass (139/139) ensuring no regression in default behavior

The detailed list of upstream changes can be found at
https://github.com/rustls/rustls/releases.
