//! Hello (ClientHello) policy abstractions for customizing TLS client hello shape.
//!
//! This module introduces a runtime-pluggable policy that can influence
//! certain aspects of ClientHello construction while preserving the
//! default upstream behavior when not provided or when using the
//! `DefaultHelloPolicy`.

use alloc::vec::Vec;

use crate::enums::CipherSuite;

/// A browser-like policy with simple presets.
#[derive(Clone, Debug, Default)]
pub struct BrowserLikePolicy {
    alpn: Option<Vec<Vec<u8>>>,
    cipher_order: Option<Vec<CipherSuite>>,
    ext_seed: Option<u16>,
}

impl BrowserLikePolicy {
    /// A reasonable approximation of recent Chrome ordering and ALPN.
    /// This intentionally keeps the list minimal and relies on the caller's
    /// provider to filter unsupported suites.
    pub fn chrome_latest() -> Self {
        Self {
            alpn: Some(alloc::vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
            cipher_order: Some(alloc::vec![
                // TLS 1.3 order
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                // Reasonable TLS 1.2 fallbacks (ECDHE first, AES-128-GCM preferred)
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ]),
            // Make extension ordering deterministic for testing/fingerprinting
            ext_seed: Some(0),
        }
    }
}

impl HelloPolicy for BrowserLikePolicy {
    fn alpn(&self, current: &[Vec<u8>], _ctx: &HelloPolicyContext<'_>) -> AlpnDecision {
        match &self.alpn {
            Some(list) if !list.is_empty() => AlpnDecision::Override(list.clone()),
            _ => AlpnDecision::Inherit,
        }
    }

    fn cipher_suites(
        &self,
        current: &[CipherSuite],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<CipherSuite>> {
        let desired = self.cipher_order.as_ref()?;
        // Build re-ordered list based on desired order constrained to `current`
        let mut out = alloc::vec::Vec::with_capacity(current.len());
        for s in desired {
            if current.contains(s) && !out.contains(s) {
                out.push(*s);
            }
        }
        for s in current {
            if !out.contains(s) {
                out.push(*s);
            }
        }
        Some(out)
    }

    fn extension_order_seed(&self, default_seed: u16, _ctx: &HelloPolicyContext<'_>) -> u16 {
        self.ext_seed.unwrap_or(default_seed)
    }
}

/// Decision for ALPN handling.
#[derive(Clone, Debug)]
pub enum AlpnDecision {
    /// Do not change ALPN; inherit from current ClientConfig/inputs
    Inherit,
    /// Replace ALPN list with the provided sequence (bytes as in-wire values)
    Override(Vec<Vec<u8>>),
    /// Filter/reorder based on provided sequence: keep only those present
    /// in current list, in the given order. No new values are added.
    Filter(Vec<Vec<u8>>),
}

/// Context passed to policy methods to aid decisions.
#[derive(Clone, Debug)]
pub struct HelloPolicyContext<'a> {
    /// Whether TLS 1.2 is supported by current config (after QUIC/ECH constraints)
    pub tls12: bool,
    /// Whether TLS 1.3 is supported by current config
    pub tls13: bool,
    /// Whether this is QUIC
    pub is_quic: bool,
    /// SNI/cover name as bytes (if DNS name); otherwise empty
    pub sni: &'a [u8],
}

/// A policy that can influence how ClientHello is formed.
///
/// All methods have safe defaults and must not relax certificate verification
/// or other security checks. Implementations should be cheap and avoid heavy
/// allocations on the hot path.
pub trait HelloPolicy: Send + Sync + core::fmt::Debug {
    /// Decide how to handle ALPN. Default is `Inherit`.
    fn alpn(&self, _current: &[Vec<u8>], _ctx: &HelloPolicyContext<'_>) -> AlpnDecision {
        AlpnDecision::Inherit
    }

    /// Optionally reorder/override cipher suites. Return `None` to inherit.
    /// If returning `Some`, the provided list will be used directly (caller
    /// enforces TLS 1.2 SCSV semantics when applicable).
    fn cipher_suites(
        &self,
        _current: &[CipherSuite],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<CipherSuite>> {
        None
    }

    /// Optionally override the extension order seed. Default returns `default_seed`.
    fn extension_order_seed(&self, default_seed: u16, _ctx: &HelloPolicyContext<'_>) -> u16 {
        default_seed
    }
}

/// A policy that exactly matches upstream behavior (no changes).
#[derive(Debug, Default)]
pub struct DefaultHelloPolicy;

impl HelloPolicy for DefaultHelloPolicy {}
