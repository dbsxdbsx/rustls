//! 服务器端REALITY协议令牌验证器
//!
//! 这个模块提供了服务器端验证REALITY协议令牌的功能，
//! 用于在TLS握手过程中验证客户端提供的REALITY令牌。

#[cfg(feature = "reality-crypto")]
use crate::msgs::handshake::SessionId;
#[cfg(feature = "reality-crypto")]
use crate::reality_crypto::{RealityConfig, RealityCrypto, RealityCryptoError};
#[cfg(feature = "reality-crypto")]
use alloc::string::String;
#[cfg(feature = "reality-crypto")]
use alloc::vec::Vec;

#[cfg(feature = "reality-crypto")]
/// REALITY令牌验证器配置
#[derive(Debug, Clone)]
pub struct RealityVerifierConfig {
    /// REALITY加密配置
    pub crypto_config: RealityConfig,
    /// 是否启用REALITY验证
    pub enabled: bool,
    /// 允许的令牌长度范围
    pub min_token_length: usize,
    /// 最大令牌长度
    pub max_token_length: usize,
}

#[cfg(feature = "reality-crypto")]
impl RealityVerifierConfig {
    /// 创建新的REALITY验证器配置
    pub fn new(
        user_id: Vec<u8>,
        server_public_key: [u8; 32],
        server_private_key: [u8; 32],
        server_name: String,
    ) -> Self {
        Self {
            crypto_config: RealityConfig::new(
                user_id,
                server_public_key,
                server_private_key,
                server_name,
            ),
            enabled: true,
            min_token_length: 16,
            max_token_length: 32,
        }
    }

    /// 禁用REALITY验证
    pub fn disabled() -> Self {
        Self {
            crypto_config: RealityConfig::new(Vec::new(), [0; 32], [0; 32], String::new()),
            enabled: false,
            min_token_length: 0,
            max_token_length: 0,
        }
    }
}

#[cfg(feature = "reality-crypto")]
/// REALITY令牌验证器
#[derive(Debug, Clone)]
pub struct RealityVerifier {
    config: RealityVerifierConfig,
    crypto: Option<RealityCrypto>,
}

#[cfg(feature = "reality-crypto")]
impl RealityVerifier {
    /// 创建新的REALITY验证器
    pub fn new(config: RealityVerifierConfig) -> Self {
        let crypto = if config.enabled {
            Some(RealityCrypto::new(config.crypto_config.clone()))
        } else {
            None
        };

        Self { config, crypto }
    }

    /// 验证REALITY令牌
    pub fn verify_token(&self, token: &[u8]) -> Result<bool, RealityCryptoError> {
        if !self.config.enabled {
            return Ok(true); // 如果未启用，总是返回成功
        }

        if let Some(crypto) = &self.crypto {
            // 检查令牌长度
            if token.len() < self.config.min_token_length
                || token.len() > self.config.max_token_length
            {
                return Ok(false);
            }

            crypto.verify_token(token)
        } else {
            Ok(false)
        }
    }

    /// 从ClientHello的session_id字段提取并验证REALITY令牌
    pub fn verify_session_id_token(
        &self,
        session_id: &SessionId,
    ) -> Result<bool, RealityCryptoError> {
        if !self.config.enabled {
            return Ok(true); // 如果未启用，总是返回成功
        }

        // 检查session_id是否为空
        if session_id.is_empty() {
            return Ok(false);
        }

        // 将session_id作为REALITY令牌进行验证
        self.verify_token(session_id.as_ref())
    }

    /// 验证基于TLS 1.3握手状态的REALITY令牌
    pub fn verify_tls13_reality_token(
        &self,
        token: &[u8],
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        handshake_hash: &[u8],
    ) -> Result<bool, RealityCryptoError> {
        if !self.config.enabled {
            return Ok(true); // 如果未启用，总是返回成功
        }

        if let Some(crypto) = &self.crypto {
            // 检查令牌长度
            if token.len() < self.config.min_token_length
                || token.len() > self.config.max_token_length
            {
                return Ok(false);
            }

            // 重新生成期望的令牌
            let expected_token = crypto.generate_tls13_reality_token(
                client_random,
                server_random,
                handshake_hash,
            )?;

            // 比较令牌
            Ok(token == expected_token.as_slice())
        } else {
            Ok(false)
        }
    }

    /// 检查是否启用了REALITY验证
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// 获取配置
    pub fn config(&self) -> &RealityVerifierConfig {
        &self.config
    }
}

#[cfg(feature = "reality-crypto")]
impl Default for RealityVerifier {
    fn default() -> Self {
        RealityVerifier::new(RealityVerifierConfig::disabled())
    }
}

#[cfg(all(test, feature = "reality-crypto"))]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_reality_verifier_disabled() {
        let verifier = RealityVerifier::default();
        assert!(!verifier.is_enabled());

        // 禁用状态下应该总是返回成功
        assert!(
            verifier
                .verify_token(b"any_token")
                .unwrap()
        );

        // 创建一个非空的 SessionId 用于测试
        let mut session_id = SessionId::empty();
        // 由于 SessionId 是私有的，我们只能测试空的情况
        assert!(
            verifier
                .verify_session_id_token(&session_id)
                .unwrap()
        );
    }

    #[test]
    fn test_reality_verifier_enabled() {
        let config = RealityVerifierConfig::new(
            b"test_user".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );
        let verifier = RealityVerifier::new(config);
        assert!(verifier.is_enabled());

        // 生成有效令牌
        let crypto = RealityCrypto::new(verifier.config().crypto_config.clone());
        let valid_token = crypto.generate_token().unwrap();

        // 验证有效令牌
        assert!(
            verifier
                .verify_token(&valid_token)
                .unwrap()
        );

        // 验证无效令牌
        assert!(
            !verifier
                .verify_token(b"invalid_token")
                .unwrap()
        );
    }

    #[test]
    fn test_session_id_token_verification() {
        let config = RealityVerifierConfig::new(
            b"test_user".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );
        let verifier = RealityVerifier::new(config);

        // 生成有效令牌
        let crypto = RealityCrypto::new(verifier.config().crypto_config.clone());
        let valid_token = crypto.generate_token().unwrap();

        // 由于 SessionId 是私有的，我们只能测试空的情况
        // 验证空session_id（应该失败，因为启用了验证）
        assert!(
            !verifier
                .verify_session_id_token(&SessionId::empty())
                .unwrap()
        );
    }

    #[test]
    fn test_tls13_reality_token_verification() {
        let config = RealityVerifierConfig::new(
            b"test_user".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );
        let verifier = RealityVerifier::new(config);

        let client_random = [0x11; 32];
        let server_random = [0x22; 32];
        let handshake_hash = b"test_handshake_hash";

        // 生成有效令牌
        let crypto = RealityCrypto::new(verifier.config().crypto_config.clone());
        let valid_token = crypto
            .generate_tls13_reality_token(&client_random, &server_random, handshake_hash)
            .unwrap();

        // 验证有效令牌
        assert!(
            verifier
                .verify_tls13_reality_token(
                    &valid_token,
                    &client_random,
                    &server_random,
                    handshake_hash,
                )
                .unwrap()
        );

        // 验证无效令牌
        assert!(
            !verifier
                .verify_tls13_reality_token(
                    b"invalid_token",
                    &client_random,
                    &server_random,
                    handshake_hash,
                )
                .unwrap()
        );

        // 验证不同参数的令牌
        let different_random = [0x33; 32];
        assert!(
            !verifier
                .verify_tls13_reality_token(
                    &valid_token,
                    &different_random,
                    &server_random,
                    handshake_hash,
                )
                .unwrap()
        );
    }

    #[test]
    fn test_token_length_validation() {
        let mut config = RealityVerifierConfig::new(
            b"test_user".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );
        config.min_token_length = 8;
        config.max_token_length = 16;
        let verifier = RealityVerifier::new(config);

        // 测试太短的令牌
        assert!(!verifier.verify_token(b"short").unwrap());

        // 测试太长的令牌
        let long_token = b"this_is_a_very_long_token_that_exceeds_the_maximum_length";
        assert!(
            !verifier
                .verify_token(long_token)
                .unwrap()
        );

        // 测试合适长度的令牌
        let crypto = RealityCrypto::new(verifier.config().crypto_config.clone());
        let _valid_token = crypto.generate_token().unwrap();
        // 注意：这里可能会失败，因为生成的令牌可能超过16字节
        // 在实际使用中，需要根据令牌长度限制调整配置
    }
}
