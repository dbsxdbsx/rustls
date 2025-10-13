use alloc::vec::Vec;
use core::marker::PhantomData;

use pki_types::{CertificateDer, PrivateKeyDer};

use super::client_conn::Resumption;
use crate::builder::{ConfigBuilder, WantsVerifier};
use crate::client::{ClientConfig, EchMode, ResolvesClientCert, handy};
use crate::error::{ApiMisuse, Error};
use crate::key_log::NoKeyLog;
use crate::sign::{CertifiedKey, SingleCertAndKey};
use crate::sync::Arc;
use crate::webpki::{self, WebPkiServerVerifier};
use crate::{compress, verify};

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Enable Encrypted Client Hello (ECH) in the given mode.
    ///
    /// This requires TLS 1.3 as the only supported protocol version to meet the requirement
    /// to support ECH.  At the end, the config building process will return an error if either
    /// TLS1.3 _is not_ supported by the provider, or TLS1.2 _is_ supported.
    ///
    /// The `ClientConfig` that will be produced by this builder will be specific to the provided
    /// [`crate::client::EchConfig`] and may not be appropriate for all connections made by the program.
    /// In this case the configuration should only be shared by connections intended for domains
    /// that offer the provided [`crate::client::EchConfig`] in their DNS zone.
    pub fn with_ech(mut self, mode: EchMode) -> Self {
        self.state.client_ech_mode = Some(mode);
        self
    }
}

impl ConfigBuilder<ClientConfig, WantsVerifier> {
    /// Choose how to verify server certificates.
    ///
    /// Using this function does not configure revocation.  If you wish to
    /// configure revocation, instead use:
    ///
    /// ```diff
    /// - .with_root_certificates(root_store)
    /// + .with_webpki_verifier(
    /// +   WebPkiServerVerifier::builder_with_provider(root_store, crypto_provider)
    /// +   .with_crls(...)
    /// +   .build()?
    /// + )
    /// ```
    pub fn with_root_certificates(
        self,
        root_store: impl Into<Arc<webpki::RootCertStore>>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        let algorithms = self
            .provider
            .signature_verification_algorithms;
        self.with_webpki_verifier(
            WebPkiServerVerifier::new_without_revocation(root_store, algorithms).into(),
        )
    }

    /// Choose how to verify server certificates using a webpki verifier.
    ///
    /// See [`webpki::WebPkiServerVerifier::builder`] and
    /// [`webpki::WebPkiServerVerifier::builder_with_provider`] for more information.
    pub fn with_webpki_verifier(
        self,
        verifier: Arc<WebPkiServerVerifier>,
    ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
        ConfigBuilder {
            state: WantsClientCert {
                verifier,
                client_ech_mode: self.state.client_ech_mode,
                hello_policy: None,
            },
            provider: self.provider,
            time_provider: self.time_provider,
            side: PhantomData,
        }
    }

    /// Access configuration options whose use is dangerous and requires
    /// extra care.
    pub fn dangerous(self) -> danger::DangerousClientConfigBuilder {
        danger::DangerousClientConfigBuilder { cfg: self }
    }
}

/// Container for unsafe APIs
pub(super) mod danger {
    use core::marker::PhantomData;

    use crate::client::WantsClientCert;
    use crate::sync::Arc;
    use crate::{ClientConfig, ConfigBuilder, WantsVerifier, verify};

    /// Accessor for dangerous configuration options.
    #[derive(Debug)]
    pub struct DangerousClientConfigBuilder {
        /// The underlying ClientConfigBuilder
        pub(super) cfg: ConfigBuilder<ClientConfig, WantsVerifier>,
    }

    impl DangerousClientConfigBuilder {
        /// Set a custom certificate verifier.
        pub fn with_custom_certificate_verifier(
            self,
            verifier: Arc<dyn verify::ServerCertVerifier>,
        ) -> ConfigBuilder<ClientConfig, WantsClientCert> {
            ConfigBuilder {
                state: WantsClientCert {
                    verifier,
                    client_ech_mode: self.cfg.state.client_ech_mode,
                    hello_policy: None,
                },
                provider: self.cfg.provider,
                time_provider: self.cfg.time_provider,
                side: PhantomData,
            }
        }
    }
}

/// A config builder state where the caller needs to supply whether and how to provide a client
/// certificate.
///
/// For more information, see the [`ConfigBuilder`] documentation.
#[derive(Clone)]
pub struct WantsClientCert {
    verifier: Arc<dyn verify::ServerCertVerifier>,
    client_ech_mode: Option<EchMode>,
    hello_policy: Option<Arc<dyn super::hello_policy::HelloPolicy>>,
}

impl ConfigBuilder<ClientConfig, WantsClientCert> {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded private key as PKCS#1, PKCS#8, or SEC1. The
    /// `aws-lc-rs` and `ring` [`CryptoProvider`][crate::CryptoProvider]s support
    /// all three encodings, but other `CryptoProviders` may not.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_client_auth_cert(
        self,
        cert_chain: Vec<CertificateDer<'static>>,
        key_der: PrivateKeyDer<'static>,
    ) -> Result<ClientConfig, Error> {
        let certified_key = CertifiedKey::from_der(cert_chain, key_der, &self.provider)?;
        self.with_client_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)))
    }

    /// Set a HelloPolicy for customizing ClientHello construction.
    ///
    /// This allows runtime-pluggable policies that can influence various aspects
    /// of ClientHello construction, including REALITY protocol support.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use rustls::client::{ClientConfig, RealityHelloPolicy};
    /// # use std::sync::Arc;
    /// # #[cfg(feature = "aws-lc-rs")] {
    /// # rustls::crypto::aws_lc_rs::default_provider().install_default();
    /// let policy = RealityHelloPolicy::new()
    ///     .with_reality_token(b"example_token".to_vec());
    /// 
    /// let config = ClientConfig::builder()
    ///     .with_root_certificates(rustls::RootCertStore::empty())
    ///     .with_no_client_auth()
    ///     .with_hello_policy(Arc::new(policy));
    /// # }
    /// ```
    pub fn with_hello_policy(
        mut self,
        hello_policy: Arc<dyn super::hello_policy::HelloPolicy>,
    ) -> Self {
        self.state.hello_policy = Some(hello_policy);
        self
    }

    /// Do not support client auth.
    ///
    /// Upstream rustls 0.23 returns `ClientConfig` here (not `Result`).
    /// Restore that signature for better ecosystem compatibility (e.g. hickory-proto).
    /// This should not fail under normal provider/ECH configuration; if it does,
    /// it indicates an API misuse elsewhere, so we convert the internal Result into
    /// a controlled panic with a clear message.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
            .expect("with_no_client_auth should not fail under normal provider/ECH configuration")
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> Result<ClientConfig, Error> {
        self.provider.consistency_check()?;

        if self.state.client_ech_mode.is_some() {
            match (
                self.provider
                    .tls12_cipher_suites
                    .is_empty(),
                self.provider
                    .tls13_cipher_suites
                    .is_empty(),
            ) {
                (_, true) => return Err(ApiMisuse::EchRequiresTls13Support.into()),
                (false, _) => return Err(ApiMisuse::EchForbidsTls12Support.into()),
                (true, false) => {}
            };
        }

        Ok(ClientConfig {
            provider: self.provider,
            alpn_protocols: Vec::new(),
            resumption: Resumption::default(),
            max_fragment_size: None,
            client_auth_cert_resolver,
            enable_sni: true,
            verifier: self.state.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_secret_extraction: false,
            enable_early_data: false,
            require_ems: cfg!(feature = "fips"),
            time_provider: self.time_provider,
            cert_compressors: compress::default_cert_compressors().to_vec(),
            cert_compression_cache: Arc::new(compress::CompressionCache::default()),
            cert_decompressors: compress::default_cert_decompressors().to_vec(),
            ech_mode: self.state.client_ech_mode,
            hello_policy: self.state.hello_policy,
        })
    }
}
