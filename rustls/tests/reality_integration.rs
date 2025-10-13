//! REALITY协议集成测试
//!
//! 这个模块包含了REALITY协议的端到端集成测试，
//! 验证客户端和服务器端的完整工作流程。

use rustls::client::{ClientConfig, RealityHelloPolicy};
use rustls::reality_crypto::{RealityConfig, RealityCrypto};
use rustls::server::{RealityVerifier, RealityVerifierConfig};
use std::sync::Arc;

#[cfg(feature = "reality-crypto")]
mod tests {
    use super::*;

    /// 测试REALITY协议的完整工作流程
    #[test]
    fn test_reality_protocol_integration() {
        // 创建REALITY配置
        let user_id = b"test_user_12345".to_vec();
        let server_public_key = [0x01; 32];
        let server_private_key = [0x02; 32];
        let server_name = "example.com".to_string();

        let reality_config = RealityConfig::new(
            user_id.clone(),
            server_public_key,
            server_private_key,
            server_name.clone(),
        );

        // 创建客户端REALITY加密器
        let client_crypto = RealityCrypto::new(reality_config.clone());
        let client_token = client_crypto.generate_token().unwrap();

        // 创建客户端HelloPolicy
        let client_hello_policy =
            RealityHelloPolicy::new().with_reality_token(client_token.clone());

        // 创建客户端配置
        let client_config = ClientConfig::builder()
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
            .with_hello_policy(Arc::new(client_hello_policy));

        // 创建服务器端REALITY验证器
        let server_verifier_config =
            RealityVerifierConfig::new(user_id, server_public_key, server_private_key, server_name);
        let server_verifier = RealityVerifier::new(server_verifier_config);

        // 验证客户端令牌
        assert!(
            server_verifier
                .verify_token(&client_token)
                .unwrap()
        );

        // 测试TLS 1.3 REALITY令牌
        let client_random = [0x11; 32];
        let server_random = [0x22; 32];
        let handshake_hash = b"test_handshake_hash";

        let tls13_token = client_crypto
            .generate_tls13_reality_token(&client_random, &server_random, handshake_hash)
            .unwrap();

        assert!(
            server_verifier
                .verify_tls13_reality_token(
                    &tls13_token,
                    &client_random,
                    &server_random,
                    handshake_hash
                )
                .unwrap()
        );
    }

    /// 测试REALITY协议的错误处理
    #[test]
    fn test_reality_protocol_error_handling() {
        let user_id = b"test_user".to_vec();
        let server_public_key = [0x01; 32];
        let server_private_key = [0x02; 32];
        let server_name = "example.com".to_string();

        let reality_config =
            RealityConfig::new(user_id, server_public_key, server_private_key, server_name);

        let crypto = RealityCrypto::new(reality_config);

        // 测试无效令牌
        let invalid_token = b"invalid_token";
        assert!(
            !crypto
                .verify_token(invalid_token)
                .unwrap()
        );

        // 测试空令牌
        let empty_token = b"";
        assert!(
            !crypto
                .verify_token(empty_token)
                .unwrap()
        );

        // 测试太长的令牌
        let long_token = vec![0u8; 100];
        assert!(
            !crypto
                .verify_token(&long_token)
                .unwrap()
        );
    }

    /// 测试REALITY协议的密钥一致性
    #[test]
    fn test_reality_protocol_key_consistency() {
        let user_id = b"test_user".to_vec();
        let server_public_key = [0x01; 32];
        let server_private_key = [0x02; 32];
        let server_name = "example.com".to_string();

        // 创建两个相同的配置
        let config1 = RealityConfig::new(
            user_id.clone(),
            server_public_key,
            server_private_key,
            server_name.clone(),
        );
        let config2 =
            RealityConfig::new(user_id, server_public_key, server_private_key, server_name);

        let crypto1 = RealityCrypto::new(config1);
        let crypto2 = RealityCrypto::new(config2);

        // 相同配置应该生成相同的令牌
        let token1 = crypto1.generate_token().unwrap();
        let token2 = crypto2.generate_token().unwrap();
        assert_eq!(token1, token2);

        // 相同配置应该能够验证彼此的令牌
        assert!(crypto1.verify_token(&token2).unwrap());
        assert!(crypto2.verify_token(&token1).unwrap());
    }

    /// 测试REALITY协议的TLS 1.3集成
    #[test]
    fn test_reality_protocol_tls13_integration() {
        let user_id = b"test_user".to_vec();
        let server_public_key = [0x01; 32];
        let server_private_key = [0x02; 32];
        let server_name = "example.com".to_string();

        let reality_config =
            RealityConfig::new(user_id, server_public_key, server_private_key, server_name);

        let crypto = RealityCrypto::new(reality_config);

        // 模拟TLS 1.3握手参数
        let client_random = [0x11; 32];
        let server_random = [0x22; 32];
        let handshake_hash = b"test_handshake_hash";

        // 测试共享密钥提取
        let shared_secret = crypto
            .extract_tls13_shared_secret(&client_random, &server_random, handshake_hash)
            .unwrap();

        assert_eq!(shared_secret.len(), 32);
        assert!(!shared_secret.iter().all(|&x| x == 0));

        // 测试TLS 1.3 REALITY令牌生成
        let tls13_token = crypto
            .generate_tls13_reality_token(&client_random, &server_random, handshake_hash)
            .unwrap();

        assert!(!tls13_token.is_empty());
        assert!(tls13_token.len() <= 32);

        // 测试不同参数产生不同结果
        let different_random = [0x33; 32];
        let different_token = crypto
            .generate_tls13_reality_token(&different_random, &server_random, handshake_hash)
            .unwrap();

        assert_ne!(tls13_token, different_token);
    }

    /// 测试REALITY协议的服务器端验证
    #[test]
    fn test_reality_protocol_server_verification() {
        let user_id = b"test_user".to_vec();
        let server_public_key = [0x01; 32];
        let server_private_key = [0x02; 32];
        let server_name = "example.com".to_string();

        // 创建服务器验证器
        let verifier_config =
            RealityVerifierConfig::new(user_id, server_public_key, server_private_key, server_name);
        let verifier = RealityVerifier::new(verifier_config);

        assert!(verifier.is_enabled());

        // 创建客户端加密器
        let client_config = RealityConfig::new(
            b"test_user".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );
        let client_crypto = RealityCrypto::new(client_config);

        // 生成有效令牌
        let valid_token = client_crypto.generate_token().unwrap();
        assert!(
            verifier
                .verify_token(&valid_token)
                .unwrap()
        );

        // 测试无效令牌
        assert!(
            !verifier
                .verify_token(b"invalid_token")
                .unwrap()
        );

        // 测试TLS 1.3令牌验证
        let client_random = [0x11; 32];
        let server_random = [0x22; 32];
        let handshake_hash = b"test_handshake_hash";

        let tls13_token = client_crypto
            .generate_tls13_reality_token(&client_random, &server_random, handshake_hash)
            .unwrap();

        assert!(
            verifier
                .verify_tls13_reality_token(
                    &tls13_token,
                    &client_random,
                    &server_random,
                    handshake_hash
                )
                .unwrap()
        );
    }

    /// 测试REALITY协议的禁用状态
    #[test]
    fn test_reality_protocol_disabled_state() {
        let verifier = RealityVerifier::default();
        assert!(!verifier.is_enabled());

        // 禁用状态下应该总是返回成功
        assert!(
            verifier
                .verify_token(b"any_token")
                .unwrap()
        );
        assert!(
            verifier
                .verify_tls13_reality_token(b"any_token", &[0; 32], &[0; 32], b"any_hash")
                .unwrap()
        );
    }

    /// 测试REALITY协议的边界条件
    #[test]
    fn test_reality_protocol_edge_cases() {
        let user_id = b"test_user".to_vec();
        let server_public_key = [0x01; 32];
        let server_private_key = [0x02; 32];
        let server_name = "example.com".to_string();

        let reality_config =
            RealityConfig::new(user_id, server_public_key, server_private_key, server_name);

        let crypto = RealityCrypto::new(reality_config);

        // 测试空握手哈希
        let client_random = [0x11; 32];
        let server_random = [0x22; 32];
        let empty_hash = b"";

        let token = crypto
            .generate_tls13_reality_token(&client_random, &server_random, empty_hash)
            .unwrap();

        assert!(!token.is_empty());
        assert!(token.len() <= 32);

        // 测试很长的握手哈希
        let long_hash = vec![0u8; 1000];
        let token2 = crypto
            .generate_tls13_reality_token(&client_random, &server_random, &long_hash)
            .unwrap();

        assert!(!token2.is_empty());
        assert!(token2.len() <= 32);
        assert_ne!(token, token2);
    }
}
