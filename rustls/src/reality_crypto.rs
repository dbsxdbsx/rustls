//! REALITY协议加密实现
//!
//! 这个模块实现了REALITY协议所需的加密功能：
//! - X25519密钥交换
//! - HKDF密钥派生
//! - AES-256-GCM AEAD加密/解密

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

#[cfg(feature = "reality-crypto")]
use {
    aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce, aead::Aead},
    hkdf::Hkdf,
    sha2::Sha256,
    x25519_dalek::{PublicKey, StaticSecret},
};

/// REALITY协议加密错误
#[derive(Debug, Clone)]
pub enum RealityCryptoError {
    /// 密钥长度错误
    InvalidKeyLength,
    /// 加密失败
    EncryptionFailed,
    /// 解密失败
    DecryptionFailed,
    /// 密钥交换失败
    KeyExchangeFailed,
    /// 其他错误
    Other(String),
}

impl core::fmt::Display for RealityCryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RealityCryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            RealityCryptoError::EncryptionFailed => write!(f, "Encryption failed"),
            RealityCryptoError::DecryptionFailed => write!(f, "Decryption failed"),
            RealityCryptoError::KeyExchangeFailed => write!(f, "Key exchange failed"),
            RealityCryptoError::Other(msg) => write!(f, "Other error: {}", msg),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RealityCryptoError {}

/// REALITY协议配置
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// 用户ID
    pub user_id: Vec<u8>,
    /// 服务器公钥 (32字节)
    pub server_public_key: [u8; 32],
    /// 客户端私钥 (32字节)
    pub client_private_key: [u8; 32],
    /// 服务器名称 (用于SNI)
    pub server_name: String,
}

impl RealityConfig {
    /// 创建新的REALITY配置
    pub fn new(
        user_id: Vec<u8>,
        server_public_key: [u8; 32],
        client_private_key: [u8; 32],
        server_name: String,
    ) -> Self {
        Self {
            user_id,
            server_public_key,
            client_private_key,
            server_name,
        }
    }
}

/// REALITY协议加密器
#[derive(Debug, Clone)]
pub struct RealityCrypto {
    config: RealityConfig,
}

impl RealityCrypto {
    /// 创建新的REALITY加密器
    pub fn new(config: RealityConfig) -> Self {
        Self { config }
    }

    /// 生成REALITY认证令牌
    ///
    /// 这个过程包括：
    /// 1. X25519密钥交换
    /// 2. HKDF密钥派生
    /// 3. AES-256-GCM AEAD加密
    pub fn generate_token(&self) -> Result<Vec<u8>, RealityCryptoError> {
        // 1. X25519密钥交换
        let shared_secret = self.perform_key_exchange()?;

        // 2. HKDF密钥派生
        let (encryption_key, iv) = self.derive_keys(&shared_secret)?;

        // 3. AES-256-GCM AEAD加密
        let token = self.encrypt_user_data(&encryption_key, &iv)?;

        // 确保令牌长度不超过32字节（legacy_session_id的最大长度）
        if token.len() > 32 {
            return Err(RealityCryptoError::Other(format!(
                "Token too long: {} bytes (max 32)",
                token.len()
            )));
        }

        Ok(token)
    }

    /// 执行X25519密钥交换
    fn perform_key_exchange(&self) -> Result<[u8; 32], RealityCryptoError> {
        #[cfg(feature = "reality-crypto")]
        {
            // 使用真正的X25519实现 (x25519-dalek 1.x)
            let client_secret = StaticSecret::from(self.config.client_private_key);
            let server_public = PublicKey::from(self.config.server_public_key);

            let shared_secret = client_secret.diffie_hellman(&server_public);
            Ok(shared_secret.to_bytes())
        }

        #[cfg(not(feature = "reality-crypto"))]
        {
            // 回退到简化实现（仅用于演示）
            self.simplified_x25519(
                &self.config.client_private_key,
                &self.config.server_public_key,
            )
        }
    }

    /// 简化的X25519实现（用于演示，当reality-crypto特性未启用时）
    /// 在实际生产环境中，应该使用经过验证的加密库
    #[cfg(not(feature = "reality-crypto"))]
    fn simplified_x25519(
        &self,
        private_key: &[u8; 32],
        public_key: &[u8; 32],
    ) -> Result<[u8; 32], RealityCryptoError> {
        // 这是一个简化的实现，仅用于演示
        // 实际应该使用真正的X25519算法
        let mut shared_secret = [0u8; 32];

        // 简化的密钥交换：XOR操作（仅用于演示）
        for i in 0..32 {
            shared_secret[i] = private_key[i] ^ public_key[i];
        }

        // 添加一些确定性变换
        for i in 0..32 {
            shared_secret[i] = shared_secret[i].wrapping_add(i as u8);
        }

        Ok(shared_secret)
    }

    /// 使用HKDF派生加密密钥和IV
    fn derive_keys(
        &self,
        shared_secret: &[u8; 32],
    ) -> Result<([u8; 32], [u8; 12]), RealityCryptoError> {
        #[cfg(feature = "reality-crypto")]
        {
            // 使用真正的HKDF实现
            let hk = Hkdf::<Sha256>::new(None, shared_secret);

            // 派生加密密钥 (32字节)
            let mut encryption_key = [0u8; 32];
            hk.expand(b"REALITY_ENCRYPTION_KEY", &mut encryption_key)
                .map_err(|_| RealityCryptoError::KeyExchangeFailed)?;

            // 派生IV (12字节)
            let mut iv = [0u8; 12];
            hk.expand(b"REALITY_IV", &mut iv)
                .map_err(|_| RealityCryptoError::KeyExchangeFailed)?;

            Ok((encryption_key, iv))
        }

        #[cfg(not(feature = "reality-crypto"))]
        {
            // 回退到简化实现（仅用于演示）
            let mut encryption_key = [0u8; 32];
            let mut iv = [0u8; 12];

            // 简化的密钥派生：基于共享密钥生成加密密钥
            for i in 0..32 {
                encryption_key[i] = shared_secret[i].wrapping_add(0x42); // 添加常量
            }

            // 生成IV
            for i in 0..12 {
                iv[i] = shared_secret[i % 32].wrapping_add(0x24); // 添加不同常量
            }

            Ok((encryption_key, iv))
        }
    }

    /// 使用AES-256-GCM加密用户数据
    fn encrypt_user_data(
        &self,
        key: &[u8; 32],
        iv: &[u8; 12],
    ) -> Result<Vec<u8>, RealityCryptoError> {
        #[cfg(feature = "reality-crypto")]
        {
            // 使用真正的AES-256-GCM实现
            let cipher_key = Key::<Aes256Gcm>::from_slice(key);
            let cipher = Aes256Gcm::new(cipher_key);

            let nonce = Nonce::from_slice(iv);

            // 加密用户数据
            let ciphertext = cipher
                .encrypt(nonce, self.config.user_id.as_slice())
                .map_err(|_| RealityCryptoError::EncryptionFailed)?;

            Ok(ciphertext)
        }

        #[cfg(not(feature = "reality-crypto"))]
        {
            // 回退到简化实现（仅用于演示）
            let mut ciphertext = Vec::with_capacity(self.config.user_id.len() + 16); // 数据 + 16字节标签

            // 简化的"加密"：XOR + 简单变换
            for (i, &byte) in self.config.user_id.iter().enumerate() {
                let encrypted_byte = byte ^ key[i % 32] ^ iv[i % 12];
                ciphertext.push(encrypted_byte);
            }

            // 简化的认证标签生成
            let mut tag = [0u8; 16];
            for i in 0..16 {
                tag[i] = key[i % 32] ^ iv[i % 12] ^ (i as u8);
            }
            ciphertext.extend_from_slice(&tag);

            Ok(ciphertext)
        }
    }

    /// 验证REALITY令牌（服务器端使用）
    pub fn verify_token(&self, token: &[u8]) -> Result<bool, RealityCryptoError> {
        #[cfg(feature = "reality-crypto")]
        {
            if token.len() < 16 {
                return Ok(false); // 令牌太短，无法包含认证标签
            }

            // 重新生成共享密钥
            let shared_secret = self.perform_key_exchange()?;
            let (encryption_key, iv) = self.derive_keys(&shared_secret)?;

            // 使用真正的AES-256-GCM解密
            let cipher_key = Key::<Aes256Gcm>::from_slice(&encryption_key);
            let cipher = Aes256Gcm::new(cipher_key);
            let nonce = Nonce::from_slice(&iv);

            // 尝试解密
            match cipher.decrypt(nonce, token) {
                Ok(decrypted) => {
                    // 验证解密后的数据是否与原始用户ID匹配
                    Ok(decrypted == self.config.user_id)
                }
                Err(_) => Ok(false), // 解密失败，令牌无效
            }
        }

        #[cfg(not(feature = "reality-crypto"))]
        {
            if token.len() < 16 {
                return Ok(false); // 令牌太短，无法包含认证标签
            }

            // 重新生成共享密钥
            let shared_secret = self.perform_key_exchange()?;
            let (encryption_key, iv) = self.derive_keys(&shared_secret)?;

            // 解密并验证
            let data_len = token.len() - 16;
            let mut decrypted = Vec::with_capacity(data_len);

            for i in 0..data_len {
                let decrypted_byte = token[i] ^ encryption_key[i % 32] ^ iv[i % 12];
                decrypted.push(decrypted_byte);
            }

            // 验证认证标签
            let expected_tag = &token[data_len..];
            let mut computed_tag = [0u8; 16];
            for i in 0..16 {
                computed_tag[i] = encryption_key[i % 32] ^ iv[i % 12] ^ (i as u8);
            }

            Ok(expected_tag == computed_tag.as_slice())
        }
    }

    /// 从TLS 1.3握手过程中提取共享密钥
    ///
    /// 这个方法模拟了TLS 1.3握手过程中的密钥提取过程，
    /// 用于REALITY协议中生成与TLS握手相关的认证令牌。
    pub fn extract_tls13_shared_secret(
        &self,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        handshake_hash: &[u8],
    ) -> Result<Vec<u8>, RealityCryptoError> {
        #[cfg(feature = "reality-crypto")]
        {
            // 执行X25519密钥交换
            let shared_secret = self.perform_key_exchange()?;

            // 使用HKDF提取TLS 1.3风格的共享密钥
            let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);

            // 构造HKDF info参数，模拟TLS 1.3的密钥提取过程
            let mut info = Vec::new();
            info.extend_from_slice(b"tls13 reality shared secret");
            info.extend_from_slice(client_random);
            info.extend_from_slice(server_random);
            info.extend_from_slice(&(handshake_hash.len() as u32).to_be_bytes());
            info.extend_from_slice(handshake_hash);

            // 提取32字节的共享密钥
            let mut derived_key = [0u8; 32];
            hkdf.expand(&info, &mut derived_key)
                .map_err(|_| RealityCryptoError::KeyExchangeFailed)?;

            Ok(derived_key.to_vec())
        }

        #[cfg(not(feature = "reality-crypto"))]
        {
            // 在没有加密库的情况下，使用简化的密钥派生
            let shared_secret = self.perform_key_exchange()?;

            // 简单的哈希组合
            let mut combined = Vec::new();
            combined.extend_from_slice(&shared_secret);
            combined.extend_from_slice(b"tls13 reality shared secret");
            combined.extend_from_slice(client_random);
            combined.extend_from_slice(server_random);
            combined.extend_from_slice(handshake_hash);

            // 使用简单的XOR哈希
            let mut result = [0u8; 32];
            for (i, &byte) in combined.iter().enumerate() {
                result[i % 32] ^= byte;
            }

            Ok(result.to_vec())
        }
    }

    /// 生成基于TLS 1.3握手状态的REALITY令牌
    ///
    /// 这个方法结合了TLS 1.3握手状态和REALITY协议，
    /// 生成一个与特定TLS握手会话关联的认证令牌。
    pub fn generate_tls13_reality_token(
        &self,
        client_random: &[u8; 32],
        server_random: &[u8; 32],
        handshake_hash: &[u8],
    ) -> Result<Vec<u8>, RealityCryptoError> {
        // 提取TLS 1.3共享密钥
        let tls13_secret =
            self.extract_tls13_shared_secret(client_random, server_random, handshake_hash)?;

        #[cfg(feature = "reality-crypto")]
        {
            // 使用TLS 1.3共享密钥作为额外的认证数据
            let mut additional_data = Vec::new();
            additional_data.extend_from_slice(&self.config.user_id);
            additional_data.extend_from_slice(&tls13_secret);
            additional_data.extend_from_slice(client_random);
            additional_data.extend_from_slice(server_random);

            // 使用AES-256-GCM加密
            let shared_secret = self.perform_key_exchange()?;
            let (encryption_key, iv) = self.derive_keys(&shared_secret)?;

            let cipher_key = Key::<Aes256Gcm>::from_slice(&encryption_key);
            let cipher = Aes256Gcm::new(cipher_key);
            let nonce = Nonce::from_slice(&iv);

            let encrypted = cipher
                .encrypt(nonce, additional_data.as_ref())
                .map_err(|_| RealityCryptoError::EncryptionFailed)?;

            // 确保加密后的令牌长度不超过32字节
            if encrypted.len() > 32 {
                // 如果太长，截取前32字节
                Ok(encrypted[..32].to_vec())
            } else {
                Ok(encrypted)
            }
        }

        #[cfg(not(feature = "reality-crypto"))]
        {
            // 简化的令牌生成，确保不超过32字节
            let mut combined = Vec::new();
            combined.extend_from_slice(&self.config.user_id);
            combined.extend_from_slice(&tls13_secret);
            combined.extend_from_slice(client_random);
            combined.extend_from_slice(server_random);

            // 使用哈希来生成固定长度的令牌
            let mut token = [0u8; 32];
            for (i, &byte) in combined.iter().enumerate() {
                token[i % 32] ^= byte;
            }

            // 添加简单的认证标签（覆盖前16字节）
            for i in 0..16 {
                token[i] ^= (i as u8) ^ 0xAA; // 添加一些变化
            }

            Ok(token.to_vec())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_reality_crypto_basic() {
        let config = RealityConfig::new(
            b"test_user".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );

        let crypto = RealityCrypto::new(config);

        // 测试令牌生成
        let token = crypto.generate_token().unwrap();
        assert!(token.len() <= 32);
        assert!(!token.is_empty());

        // 测试令牌验证
        let is_valid = crypto.verify_token(&token).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_reality_crypto_different_keys() {
        let config1 = RealityConfig::new(
            b"user1".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );

        let config2 = RealityConfig::new(
            b"user1".to_vec(),
            [0x03; 32], // 不同的服务器公钥
            [0x02; 32],
            "example.com".to_string(),
        );

        let crypto1 = RealityCrypto::new(config1);
        let crypto2 = RealityCrypto::new(config2);

        let token1 = crypto1.generate_token().unwrap();
        let token2 = crypto2.generate_token().unwrap();

        // 不同密钥应该生成不同令牌
        assert_ne!(token1, token2);

        // 令牌应该只能被对应的加密器验证
        assert!(crypto1.verify_token(&token1).unwrap());
        assert!(!crypto1.verify_token(&token2).unwrap());
        assert!(crypto2.verify_token(&token2).unwrap());
        assert!(!crypto2.verify_token(&token1).unwrap());
    }

    #[test]
    fn test_reality_crypto_invalid_token() {
        let config = RealityConfig::new(
            b"test_user".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );

        let crypto = RealityCrypto::new(config);

        // 测试无效令牌
        let invalid_token = b"invalid_token";
        let is_valid = crypto
            .verify_token(invalid_token)
            .unwrap();
        assert!(!is_valid);

        // 测试空令牌
        let empty_token = b"";
        let is_valid = crypto
            .verify_token(empty_token)
            .unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_tls13_shared_secret_extraction() {
        let config = RealityConfig::new(
            b"test_user".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );

        let crypto = RealityCrypto::new(config);

        // 模拟TLS 1.3握手参数
        let client_random = [0x11; 32];
        let server_random = [0x22; 32];
        let handshake_hash = b"test_handshake_hash";

        // 测试共享密钥提取
        let shared_secret = crypto
            .extract_tls13_shared_secret(&client_random, &server_random, handshake_hash)
            .unwrap();

        assert_eq!(shared_secret.len(), 32);
        assert!(!shared_secret.iter().all(|&x| x == 0)); // 不应该全是零

        // 相同参数应该产生相同结果
        let shared_secret2 = crypto
            .extract_tls13_shared_secret(&client_random, &server_random, handshake_hash)
            .unwrap();
        assert_eq!(shared_secret, shared_secret2);

        // 不同参数应该产生不同结果
        let different_hash = b"different_handshake_hash";
        let shared_secret3 = crypto
            .extract_tls13_shared_secret(&client_random, &server_random, different_hash)
            .unwrap();
        assert_ne!(shared_secret, shared_secret3);
    }

    #[test]
    fn test_tls13_reality_token_generation() {
        let config = RealityConfig::new(
            b"test_user".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );

        let crypto = RealityCrypto::new(config);

        // 模拟TLS 1.3握手参数
        let client_random = [0x11; 32];
        let server_random = [0x22; 32];
        let handshake_hash = b"test_handshake_hash";

        // 测试TLS 1.3 REALITY令牌生成
        let token = crypto
            .generate_tls13_reality_token(&client_random, &server_random, handshake_hash)
            .unwrap();

        assert!(!token.is_empty());
        assert!(token.len() <= 32); // 令牌长度限制

        // 相同参数应该产生相同结果
        let token2 = crypto
            .generate_tls13_reality_token(&client_random, &server_random, handshake_hash)
            .unwrap();
        assert_eq!(token, token2);

        // 不同参数应该产生不同结果
        let different_random = [0x33; 32];
        let token3 = crypto
            .generate_tls13_reality_token(&different_random, &server_random, handshake_hash)
            .unwrap();
        assert_ne!(token, token3);
    }

    #[test]
    fn test_tls13_reality_token_consistency() {
        let config1 = RealityConfig::new(
            b"user1".to_vec(),
            [0x01; 32],
            [0x02; 32],
            "example.com".to_string(),
        );

        let config2 = RealityConfig::new(
            b"user1".to_vec(),
            [0x01; 32], // 相同配置
            [0x02; 32],
            "example.com".to_string(),
        );

        let crypto1 = RealityCrypto::new(config1);
        let crypto2 = RealityCrypto::new(config2);

        let client_random = [0x11; 32];
        let server_random = [0x22; 32];
        let handshake_hash = b"test_handshake_hash";

        // 相同配置应该产生相同的TLS 1.3令牌
        let token1 = crypto1
            .generate_tls13_reality_token(&client_random, &server_random, handshake_hash)
            .unwrap();

        let token2 = crypto2
            .generate_tls13_reality_token(&client_random, &server_random, handshake_hash)
            .unwrap();

        assert_eq!(token1, token2);
    }
}
