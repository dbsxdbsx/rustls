#![cfg(test)]

use crate::client::{BrowserLikePolicy, HelloPolicy};
use crate::client::hello_policy::{HelloPolicyContext, ListPosition};
use crate::enums::SignatureScheme;
use crate::msgs::enums::NamedGroup;

#[test]
fn test_grease_in_supported_groups() {
    let policy = BrowserLikePolicy::chrome_latest()
        .with_grease_lists(true)
        .with_grease_position(ListPosition::Head)
        .with_grease_count(1);

    let ctx = HelloPolicyContext {
        tls12: false,
        tls13: true,
        is_quic: false,
        sni: &[],
    };

    // Apply GREASE to supported groups
    let current_groups = vec![
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ];

    let result = policy.supported_groups(&current_groups, &ctx);
    assert!(result.is_some());

    let groups = result.unwrap();
    // Should have original groups plus possibly reordered
    assert!(groups.contains(&NamedGroup::X25519));

    // Chrome preset should prefer X25519
    let first_non_grease = groups
        .iter()
        .find(|g| !matches!(g, NamedGroup::Unknown(_)))
        .unwrap();
    assert_eq!(*first_non_grease, NamedGroup::X25519);
}

#[test]
fn test_grease_in_signature_algorithms() {
    let policy = BrowserLikePolicy::chrome_latest()
        .with_grease_lists(true)
        .with_grease_position(ListPosition::Tail)
        .with_grease_count(1);

    let ctx = HelloPolicyContext {
        tls12: false,
        tls13: true,
        is_quic: false,
        sni: &[],
    };

    // Apply GREASE to signature algorithms
    let current_sigs = vec![
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA256,
    ];

    let result = policy.signature_algorithms(&current_sigs, &ctx);
    assert!(result.is_some());

    let sigs = result.unwrap();
    // Should contain all original algorithms
    assert!(sigs.contains(&SignatureScheme::ECDSA_NISTP256_SHA256));
    assert!(sigs.contains(&SignatureScheme::ED25519));
    assert!(sigs.contains(&SignatureScheme::RSA_PSS_SHA256));
}

#[test]
fn test_grease_disabled() {
    let policy = BrowserLikePolicy::chrome_latest()
        .with_grease_lists(false);

    let ctx = HelloPolicyContext {
        tls12: false,
        tls13: true,
        is_quic: false,
        sni: &[],
    };

    assert!(!policy.grease_lists(&ctx));
}

#[test]
fn test_grease_deterministic_with_seed() {
    use crate::client::hs::choose_grease;

    // Same seed should produce same GREASE value
    let grease1 = choose_grease(42);
    let grease2 = choose_grease(42);
    assert_eq!(grease1, grease2);

    // Different seeds should (likely) produce different values
    let grease3 = choose_grease(43);
    // This might occasionally fail due to collision, but very unlikely
    assert_ne!(grease1, grease3);

    // Verify it's a valid GREASE value
    const VALID_GREASE: &[u16] = &[
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    ];
    assert!(VALID_GREASE.contains(&grease1));
}

#[test]
fn test_multiple_key_shares() {
    let policy = BrowserLikePolicy::chrome_latest()
        .with_preferred_key_shares(vec![
            NamedGroup::X25519,
            NamedGroup::secp256r1,
        ]);

    let ctx = HelloPolicyContext {
        tls12: false,
        tls13: true,
        is_quic: false,
        sni: &[],
    };

    let available = vec![
        NamedGroup::X25519,
        NamedGroup::secp256r1,
        NamedGroup::secp384r1,
    ];

    let result = policy.preferred_key_share_groups(&available, &ctx);
    assert!(result.is_some());

    let shares = result.unwrap();
    assert_eq!(shares.len(), 2);
    assert_eq!(shares[0], NamedGroup::X25519);
    assert_eq!(shares[1], NamedGroup::secp256r1);
}

#[test]
fn test_padding_configuration() {
    use crate::client::hello_policy::PaddingPosition;
    use crate::msgs::enums::ExtensionType;

    let policy = BrowserLikePolicy::chrome_latest()
        .with_padding_len(Some(256))
        .with_padding_position(PaddingPosition::Before(ExtensionType::SupportedVersions));

    let ctx = HelloPolicyContext {
        tls12: false,
        tls13: true,
        is_quic: false,
        sni: &[],
    };

    assert_eq!(policy.tls13_padding_len(&ctx), Some(256));
    assert_eq!(
        policy.tls13_padding_position(&ctx),
        PaddingPosition::Before(ExtensionType::SupportedVersions)
    );
}

#[test]
fn test_session_control() {
    let policy = BrowserLikePolicy::chrome_latest();

    let ctx = HelloPolicyContext {
        tls12: false,
        tls13: true,
        is_quic: false,
        sni: &[],
    };

    // Chrome preset disables PSK and early data by default
    assert!(policy.disable_psk(&ctx));
    assert!(policy.disable_early_data(&ctx));
    assert!(policy.disable_session_ticket(&ctx));
}
