# HelloPolicy for Customizable ClientHello

This fork adds a HelloPolicy framework to rustls 0.23.x, enabling runtime customization of TLS ClientHello fingerprints while maintaining full compatibility with the upstream API.

## Features

### Core Capabilities
- **Runtime-pluggable HelloPolicy**: Customize ClientHello construction without modifying library code
- **Browser-like presets**: Pre-configured policies mimicking Chrome, Firefox, iOS, etc.
- **Zero-overhead when unused**: Default behavior matches upstream exactly when no policy is set
- **TLS 1.3 focused**: Primary support for TLS 1.3 with extensible TLS 1.2 support

### Customizable Elements
- **ALPN protocols**: Override, filter, or reorder application protocols
- **Cipher suites**: Control ordering and selection
- **Extension ordering**: Deterministic or randomized extension placement
- **Supported groups**: Filter and reorder elliptic curves/key exchange groups
- **Signature algorithms**: Customize signature scheme preferences
- **Key shares**: Single or multiple key shares with configurable groups
- **GREASE values**: RFC 8701 compliant GREASE insertion in lists
- **Padding extension**: Configurable length and positioning
- **Session controls**: Fine-grained control over PSK, early data, and session tickets

## Usage

### Basic Example

```rust
use rustls::client::{ClientConfig, BrowserLikePolicy};
use std::sync::Arc;

// Create a config with Chrome-like ClientHello
let mut config = ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();

// Apply Chrome preset
config.hello_policy = Some(Arc::new(BrowserLikePolicy::chrome_latest()));

// Use the config normally
let mut conn = ClientConnection::new(Arc::new(config), server_name)?;
```

### Advanced Customization

```rust
use rustls::client::{BrowserLikePolicy, HelloPolicy};
use rustls::client::hello_policy::{ListPosition, PaddingPosition};
use rustls::msgs::enums::{ExtensionType, NamedGroup};

let policy = BrowserLikePolicy::chrome_latest()
    // Configure GREASE
    .with_grease_lists(true)
    .with_grease_position(ListPosition::Head)
    .with_grease_count(1)

    // Configure padding
    .with_padding_len(Some(256))
    .with_padding_position(PaddingPosition::Before(ExtensionType::SupportedVersions))

    // Multiple key shares
    .with_preferred_key_shares(vec![
        NamedGroup::X25519,
        NamedGroup::secp256r1,
    ])

    // Deterministic extension ordering for testing
    .with_extension_order_seed(0)

    // Test-only: fixed random for golden samples
    .with_fixed_client_random([0u8; 32])
    .with_force_empty_session_id(true);

config.hello_policy = Some(Arc::new(policy));
```

### Custom Policy Implementation

```rust
use rustls::client::hello_policy::{HelloPolicy, HelloPolicyContext, AlpnDecision};

#[derive(Debug)]
struct MyCustomPolicy;

impl HelloPolicy for MyCustomPolicy {
    fn alpn(&self, current: &[Vec<u8>], ctx: &HelloPolicyContext<'_>) -> AlpnDecision {
        // Custom ALPN logic
        if ctx.tls13 {
            AlpnDecision::Override(vec![b"h3".to_vec()])
        } else {
            AlpnDecision::Inherit
        }
    }

    fn cipher_suites(
        &self,
        current: &[CipherSuite],
        ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<CipherSuite>> {
        // Custom cipher suite ordering
        let mut suites = current.to_vec();
        suites.sort_by_key(|s| match s {
            CipherSuite::TLS13_AES_128_GCM_SHA256 => 0,
            CipherSuite::TLS13_CHACHA20_POLY1305_SHA256 => 1,
            _ => 99,
        });
        Some(suites)
    }

    // ... other methods with default implementations
}
```

## Testing

### Golden Sample Testing

Generate deterministic ClientHello for testing:

```rust
// Run the ignored test to generate hex output
cargo test --lib client::test::print_chrome_latest_full_clienthello_hex -- --ignored --nocapture

// Or use the example program
cargo run --example generate_clienthello > clienthello.hex
```

### GREASE Testing

```rust
cargo test --lib client::test_grease
```

Tests cover:
- GREASE insertion in supported groups and signature algorithms
- Deterministic GREASE with seeds
- Multiple key share configuration
- Padding positioning
- Session control flags

## Design Principles

1. **Compatibility First**: No changes to existing public API; new features are opt-in
2. **Runtime Configuration**: Policies are applied at runtime, not compile-time
3. **Security by Default**: Unsafe operations are never allowed; policies can only customize protocol-compliant behavior
4. **Zero Overhead**: When no policy is set, performance and behavior match upstream exactly
5. **Testability**: Deterministic modes for golden testing and fingerprint validation

## Implementation Details

### File Structure
- `rustls/src/client/hello_policy.rs`: Core HelloPolicy trait and implementations
- `rustls/src/client/hs.rs`: Integration points in handshake logic
- `rustls/src/client/test.rs`: Tests for policy application
- `rustls/src/client/test_grease.rs`: GREASE-specific tests

### Key Integration Points
1. **ClientHelloInput::new()**: ALPN and extension seed policy application
2. **emit_client_hello_for_retry()**: Main ClientHello construction with policy hooks
3. **prepare_resumption()**: PSK and early data policy controls
4. **initial_key_shares()**: Multiple key share support

### Testing Infrastructure
- Golden samples in `rustls/tests/data/hello/`
- Deterministic random and session ID for reproducible tests
- Extension ordering verification
- GREASE value validation

## Compatibility

- **rustls**: 0.23.x (tested with 0.23.32)
- **tokio-rustls**: 0.26.x (no changes needed)
- **reqwest**: Compatible via rustls
- **tokio-tungstenite**: Compatible via rustls

## Future Enhancements

- [ ] TLS 1.2 HelloPolicy support
- [ ] Extension-level GREASE (not just list GREASE)
- [ ] More browser presets (Firefox, Safari, Edge)
- [ ] Automated fingerprint updates from real browsers
- [ ] Performance optimizations for policy evaluation

## Contributing

When adding new policies or presets:
1. Implement in `hello_policy.rs`
2. Add tests in `test_grease.rs` or `test.rs`
3. Generate golden samples for verification
4. Update this documentation

## License

This fork maintains the same license as upstream rustls (Apache 2.0 / ISC / MIT).
