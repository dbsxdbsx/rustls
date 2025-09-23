//! Hello (ClientHello) policy abstractions for customizing TLS client hello shape.
//!
//! This module introduces a runtime-pluggable policy that can influence
//! certain aspects of ClientHello construction while preserving the
//! default upstream behavior when not provided or when using the
//! `DefaultHelloPolicy`.

use alloc::vec::Vec;

use crate::enums::{CipherSuite, SignatureScheme};
use crate::msgs::enums::{ExtensionType, NamedGroup};

/// A browser-like policy with simple presets.
#[derive(Clone, Debug, Default)]
pub struct BrowserLikePolicy {
    alpn: Option<Vec<Vec<u8>>>,
    cipher_order: Option<Vec<CipherSuite>>,
    ext_seed: Option<u16>,
    // Advanced controls
    groups: Option<Vec<NamedGroup>>, // SupportedGroups order/subset
    sig_algs: Option<Vec<SignatureScheme>>, // SignatureAlgorithms order/subset
    preferred_kx: Option<NamedGroup>, // Preferred single KeyShare group (back-compat)
    preferred_kx_multi: Option<Vec<NamedGroup>>, // Preferred multiple KeyShare groups (order matters)
    padding_len: Option<usize>,                  // TLS1.3 Padding extension length (bytes)
    // GREASE for lists (SupportedGroups/SignatureSchemes)
    grease_lists: bool,
    grease_pos: Option<ListPosition>, // GREASE insertion position
    grease_count: usize,              // number of GREASE items to insert per list (0/1)
    // Additional GREASE features
    grease_key_share: bool,          // Enable KeyShare GREASE
    grease_extensions: bool,         // Enable Extension-type GREASE
    grease_extension_values: bool,   // Enable GREASE extension values
    // Padding position control
    padding_pos: Option<PaddingPosition>,
    // Session controls
    disable_psk: bool,
    disable_early_data: bool,
    disable_session_ticket: bool,
    // Test-only stabilization hooks (no-op unless set)
    fixed_random: Option<[u8; 32]>,
    force_empty_session_id: bool,
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
            // Advanced: closer to Chrome defaults
            groups: Some(alloc::vec![NamedGroup::X25519]),
            sig_algs: Some(alloc::vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ED25519,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
            ]),
            preferred_kx: Some(NamedGroup::X25519),
            preferred_kx_multi: None,
            padding_len: None,  // off by default
            grease_lists: true, // Chrome greases various lists
            grease_pos: None,
            grease_count: 1,
            grease_key_share: true,      // Chrome uses KeyShare GREASE
            grease_extensions: true,     // Chrome uses Extension GREASE
            grease_extension_values: true, // Chrome uses GREASE extension values
            padding_pos: None,
            disable_psk: true,
            disable_early_data: true,
            disable_session_ticket: true,
            fixed_random: None,
            force_empty_session_id: false,
        }
    }

    // Simple builders for tests/config ergonomics
    /// Enable or disable GREASE in lists.
    pub fn with_grease_lists(mut self, on: bool) -> Self {
        self.grease_lists = on;
        self
    }
    /// Set GREASE insertion position in lists.
    pub fn with_grease_position(mut self, pos: ListPosition) -> Self {
        self.grease_pos = Some(pos);
        self
    }
    /// Set number of GREASE items to insert per list.
    pub fn with_grease_count(mut self, n: usize) -> Self {
        self.grease_count = n;
        self
    }
    /// Enable or disable KeyShare GREASE.
    pub fn with_grease_key_share(mut self, on: bool) -> Self {
        self.grease_key_share = on;
        self
    }
    /// Enable or disable Extension-type GREASE.
    pub fn with_grease_extensions(mut self, on: bool) -> Self {
        self.grease_extensions = on;
        self
    }
    /// Enable or disable GREASE extension values.
    pub fn with_grease_extension_values(mut self, on: bool) -> Self {
        self.grease_extension_values = on;
        self
    }
    /// Set TLS 1.3 Padding extension length in bytes.
    pub fn with_padding_len(mut self, len: Option<usize>) -> Self {
        self.padding_len = len;
        self
    }
    /// Set Padding extension position in the extension list.
    pub fn with_padding_position(mut self, pos: PaddingPosition) -> Self {
        self.padding_pos = Some(pos);
        self
    }
    /// Place Padding extension before the specified extension type.
    pub fn with_padding_before(mut self, ext: ExtensionType) -> Self {
        self.padding_pos = Some(PaddingPosition::Before(ext));
        self
    }
    /// Place Padding extension after the specified extension type.
    pub fn with_padding_after(mut self, ext: ExtensionType) -> Self {
        self.padding_pos = Some(PaddingPosition::After(ext));
        self
    }
    /// Set extension order seed for deterministic ordering.
    pub fn with_extension_order_seed(mut self, seed: u16) -> Self {
        self.ext_seed = Some(seed);
        self
    }
    /// Set preferred key share groups (multiple).
    pub fn with_preferred_key_shares(mut self, groups: Vec<NamedGroup>) -> Self {
        self.preferred_kx_multi = Some(groups);
        self
    }
    /// Test-only: Set fixed client random bytes for deterministic testing.
    pub fn with_fixed_client_random(mut self, bytes: [u8; 32]) -> Self {
        self.fixed_random = Some(bytes);
        self
    }
    /// Test-only: Force empty session ID for deterministic testing.
    pub fn with_force_empty_session_id(mut self, on: bool) -> Self {
        self.force_empty_session_id = on;
        self
    }
}

impl HelloPolicy for BrowserLikePolicy {
    fn alpn(&self, _current: &[Vec<u8>], _ctx: &HelloPolicyContext<'_>) -> AlpnDecision {
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
        let mut out = Vec::with_capacity(current.len());
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

    fn supported_groups(
        &self,
        current: &[NamedGroup],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<NamedGroup>> {
        let desired = self.groups.as_ref()?;
        let mut out = Vec::with_capacity(current.len());
        for g in desired {
            if current.contains(g) && !out.contains(g) {
                out.push(*g);
            }
        }
        for g in current {
            if !out.contains(g) {
                out.push(*g);
            }
        }
        Some(out)
    }

    fn signature_algorithms(
        &self,
        current: &[SignatureScheme],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<SignatureScheme>> {
        let desired = self.sig_algs.as_ref()?;
        let mut out = Vec::with_capacity(current.len());
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

    fn preferred_key_share_group(
        &self,
        available: &[NamedGroup],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<NamedGroup> {
        let g = self.preferred_kx?;
        available.contains(&g).then_some(g)
    }

    fn preferred_key_share_groups(
        &self,
        available: &[NamedGroup],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<NamedGroup>> {
        if let Some(list) = &self.preferred_kx_multi {
            let mut out = Vec::with_capacity(list.len());
            for g in list {
                if available.contains(g) && !out.contains(g) {
                    out.push(*g);
                }
            }
            if out.is_empty() { None } else { Some(out) }
        } else if let Some(g) = self.preferred_kx {
            available
                .contains(&g)
                .then_some(alloc::vec![g])
        } else {
            None
        }
    }

    fn tls13_padding_len(&self, _ctx: &HelloPolicyContext<'_>) -> Option<usize> {
        self.padding_len
    }

    fn disable_psk(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.disable_psk
    }
    fn disable_early_data(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.disable_early_data
    }

    fn disable_session_ticket(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.disable_session_ticket
    }

    fn grease_lists(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.grease_lists
    }
    fn grease_list_count(&self, _ctx: &HelloPolicyContext<'_>) -> usize {
        self.grease_count
    }
    fn grease_list_position(&self, _ctx: &HelloPolicyContext<'_>) -> ListPosition {
        self.grease_pos
            .unwrap_or(ListPosition::Head)
    }
    fn grease_key_share(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.grease_key_share
    }
    fn grease_extensions(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.grease_extensions
    }
    fn grease_extension_values(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.grease_extension_values
    }
    fn tls13_padding_position(&self, _ctx: &HelloPolicyContext<'_>) -> PaddingPosition {
        self.padding_pos
            .unwrap_or(PaddingPosition::Default)
    }
    fn fixed_client_random(&self, _ctx: &HelloPolicyContext<'_>) -> Option<[u8; 32]> {
        self.fixed_random
    }
    fn force_empty_session_id(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.force_empty_session_id
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
/// Where to insert GREASE values in lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListPosition {
    Head,
    Tail,
}

/// Where to place the TLS1.3 Padding extension within the extension list.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PaddingPosition {
    Default,
    Tail,
    Before(ExtensionType),
    After(ExtensionType),
}

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

    /// Optionally filter/reorder SupportedGroups (NamedGroup) advertised.
    fn supported_groups(
        &self,
        _current: &[NamedGroup],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<NamedGroup>> {
        None
    }

    /// Optionally filter/reorder SignatureAlgorithms advertised.
    fn signature_algorithms(
        &self,
        _current: &[SignatureScheme],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<SignatureScheme>> {
        None
    }

    /// Preferred TLS1.3 key share group to generate/offer.
    fn preferred_key_share_group(
        &self,
        _available: &[NamedGroup],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<NamedGroup> {
        None
    }

    /// Preferred TLS1.3 key share groups to generate/offer (multiple).
    /// If present, the returned list will be filtered to `available` and de-duplicated preserving order.
    fn preferred_key_share_groups(
        &self,
        _available: &[NamedGroup],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<NamedGroup>> {
        None
    }

    /// If Some(len), include TLS Padding extension with `len` zero bytes.
    fn tls13_padding_len(&self, _ctx: &HelloPolicyContext<'_>) -> Option<usize> {
        None
    }

    /// Control PSK/0-RTT/session ticket behavior.
    fn disable_psk(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        false
    }

    /// Disable early data (0-RTT) even if available.
    fn disable_early_data(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        false
    }

    /// Disable session tickets even if TLS 1.2 resumption is configured.
    fn disable_session_ticket(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        false
    }

    /// If true, insert a GREASE item into certain ClientHello lists.
    fn grease_lists(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        false
    }
    /// Number of GREASE items to insert into each applicable list.
    fn grease_list_count(&self, _ctx: &HelloPolicyContext<'_>) -> usize {
        1
    }

    /// Where to insert GREASE items in lists (head/tail).
    fn grease_list_position(&self, _ctx: &HelloPolicyContext<'_>) -> ListPosition {
        ListPosition::Head
    }

    /// If true, insert a GREASE KeyShare.
    fn grease_key_share(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        false
    }

    /// If true, insert GREASE extension types.
    fn grease_extensions(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        false
    }

    /// If true, insert GREASE extension values.
    fn grease_extension_values(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        false
    }

    /// Control TLS1.3 Padding extension placement.
    fn tls13_padding_position(&self, _ctx: &HelloPolicyContext<'_>) -> PaddingPosition {
        PaddingPosition::Default
    }

    /// Test-only: if Some, use these 32 bytes as ClientHello.random
    fn fixed_client_random(&self, _ctx: &HelloPolicyContext<'_>) -> Option<[u8; 32]> {
        None
    }

    /// Test-only: if true, force legacy SessionID to be empty (TLS 1.3)
    fn force_empty_session_id(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        false
    }

    /// REALITY support: modify ClientHello bytes just before sending.
    /// This allows injecting REALITY authentication tokens into legacy_session_id.
    /// 
    /// If this method returns `Some(modified_bytes)`, those bytes will be sent instead
    /// of the original ClientHello. If `None`, the original ClientHello is sent unchanged.
    /// 
    /// WARNING: Modifying ClientHello bytes incorrectly can break the TLS handshake!
    /// This method should only be used by implementations that understand the TLS protocol.
    fn reality_inject_clienthello(&self, _original_bytes: &[u8], _ctx: &HelloPolicyContext<'_>) -> Option<Vec<u8>> {
        None
    }
}

/// A policy that exactly matches upstream behavior (no changes).
#[derive(Debug, Default)]
pub struct DefaultHelloPolicy;

impl HelloPolicy for DefaultHelloPolicy {}
