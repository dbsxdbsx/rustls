//! REALITY协议支持的HelloPolicy实现示例
//!
//! 这个模块提供了一个HelloPolicy实现，可以向ClientHello的legacy_session_id字段
//! 注入REALITY协议所需的AEAD加密认证令牌。

use alloc::vec::Vec;
use crate::client::hello_policy::{HelloPolicy, HelloPolicyContext};
use crate::enums::CipherSuite;

/// 用于REALITY协议的HelloPolicy实现
/// 
/// 这个实现可以在ClientHello发送前修改其字节内容，特别是向legacy_session_id
/// 字段注入REALITY协议所需的AEAD加密认证令牌。
#[derive(Debug, Clone)]
pub struct RealityHelloPolicy {
    /// 要注入到legacy_session_id字段的AEAD加密令牌
    /// 如果为None，则不进行任何注入
    pub reality_token: Option<Vec<u8>>,
    /// Chrome风格的cipher suite顺序
    pub cipher_order: Option<Vec<CipherSuite>>,
    /// 是否启用GREASE
    pub enable_grease: bool,
}

impl RealityHelloPolicy {
    /// 创建新的RealityHelloPolicy
    pub fn new() -> Self {
        Self {
            reality_token: None,
            cipher_order: Some(alloc::vec![
                // TLS 1.3 优先顺序（模仿Chrome）
                CipherSuite::TLS13_AES_128_GCM_SHA256,
                CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                CipherSuite::TLS13_AES_256_GCM_SHA384,
                // TLS 1.2 回退
                CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            ]),
            enable_grease: true,
        }
    }

    /// 设置REALITY认证令牌
    pub fn with_reality_token(mut self, token: Vec<u8>) -> Self {
        self.reality_token = Some(token);
        self
    }

    /// 设置cipher suite顺序
    pub fn with_cipher_order(mut self, order: Vec<CipherSuite>) -> Self {
        self.cipher_order = Some(order);
        self
    }

    /// 启用/禁用GREASE
    pub fn with_grease(mut self, enable: bool) -> Self {
        self.enable_grease = enable;
        self
    }

    /// 将REALITY令牌注入到ClientHello的legacy_session_id字段
    fn inject_reality_token(&self, client_hello_bytes: &[u8]) -> Option<Vec<u8>> {
        let token = self.reality_token.as_ref()?;
        if token.is_empty() || token.len() > 32 {
            // legacy_session_id字段最大长度为32字节
            return None;
        }

        let mut modified_bytes = client_hello_bytes.to_vec();
        
        // 查找legacy_session_id字段的位置
        // ClientHello结构：
        // - Content Type (1 byte)
        // - Version (2 bytes)
        // - Length (2 bytes)
        // - Handshake Type (1 byte) 
        // - Handshake Length (3 bytes)
        // - Client Version (2 bytes)
        // - Random (32 bytes)
        // - Session ID Length (1 byte)
        // - Session ID (variable, 0-32 bytes)
        
        if modified_bytes.len() < 5 + 4 + 2 + 32 + 1 {
            return None; // 消息太短
        }

        // 跳过TLS记录头部 (5 bytes) + 握手头部 (4 bytes) + 客户端版本 (2 bytes) + 随机数 (32 bytes)
        let session_id_len_offset = 5 + 4 + 2 + 32;
        let session_id_len = modified_bytes[session_id_len_offset];
        
        // 替换session_id长度和内容
        modified_bytes[session_id_len_offset] = token.len() as u8;
        
        // 计算session_id数据的开始位置
        let session_id_start = session_id_len_offset + 1;
        let original_session_id_end = session_id_start + session_id_len as usize;
        
        // 替换session_id数据
        let mut new_bytes = Vec::with_capacity(modified_bytes.len() - session_id_len as usize + token.len());
        new_bytes.extend_from_slice(&modified_bytes[..session_id_start]);
        new_bytes.extend_from_slice(token);
        new_bytes.extend_from_slice(&modified_bytes[original_session_id_end..]);
        
        // 更新握手消息长度
        if new_bytes.len() >= 9 {
            let handshake_len = (new_bytes.len() - 5 - 4) as u32; // 总长度减去记录头和握手头
            new_bytes[6] = ((handshake_len >> 16) & 0xff) as u8;
            new_bytes[7] = ((handshake_len >> 8) & 0xff) as u8;
            new_bytes[8] = (handshake_len & 0xff) as u8;
            
            // 更新记录长度
            let record_len = (new_bytes.len() - 5) as u16;
            new_bytes[3] = ((record_len >> 8) & 0xff) as u8;
            new_bytes[4] = (record_len & 0xff) as u8;
        }
        
        Some(new_bytes)
    }
}

impl Default for RealityHelloPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl HelloPolicy for RealityHelloPolicy {
    fn cipher_suites(
        &self,
        current: &[CipherSuite],
        _ctx: &HelloPolicyContext<'_>,
    ) -> Option<Vec<CipherSuite>> {
        let desired = self.cipher_order.as_ref()?;
        let mut out = Vec::with_capacity(current.len());
        
        // 按期望顺序添加支持的cipher suites
        for s in desired {
            if current.contains(s) && !out.contains(s) {
                out.push(*s);
            }
        }
        
        // 添加其他支持但未在期望列表中的cipher suites
        for s in current {
            if !out.contains(s) {
                out.push(*s);
            }
        }
        
        Some(out)
    }

    fn grease_lists(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.enable_grease
    }

    fn grease_key_share(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.enable_grease
    }

    fn grease_extensions(&self, _ctx: &HelloPolicyContext<'_>) -> bool {
        self.enable_grease
    }

    fn reality_inject_clienthello(&self, original_bytes: &[u8], _ctx: &HelloPolicyContext<'_>) -> Option<Vec<u8>> {
        self.inject_reality_token(original_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn test_reality_token_injection() {
        let policy = RealityHelloPolicy::new()
            .with_reality_token(b"test_reality_token_123456".to_vec());
        
        // 创建一个模拟的ClientHello字节序列
        // 这只是一个简化的测试，实际的ClientHello结构会更复杂
        let mut mock_client_hello = vec![
            // TLS记录头 (5 bytes)
            0x16, 0x03, 0x01, 0x00, 0x00, // ContentType=Handshake, Version=TLS1.0, Length=待更新
            // 握手头 (4 bytes)  
            0x01, 0x00, 0x00, 0x00, // HandshakeType=ClientHello, Length=待更新
            // ClientHello
            0x03, 0x03, // Client Version = TLS 1.2
        ];
        
        // 添加32字节随机数
        mock_client_hello.extend_from_slice(&[0; 32]);
        
        // 添加session_id长度（原本为0）
        mock_client_hello.push(0x00);
        
        // 添加一些模拟的cipher suites等数据
        mock_client_hello.extend_from_slice(&[
            0x00, 0x02, // cipher suites length
            0x13, 0x01, // TLS_AES_128_GCM_SHA256
            0x01, 0x00, // compression methods length + null compression
        ]);
        
        // 更新长度字段
        let total_len = mock_client_hello.len() - 5;
        mock_client_hello[3] = ((total_len >> 8) & 0xff) as u8;
        mock_client_hello[4] = (total_len & 0xff) as u8;
        
        let handshake_len = total_len - 4;
        mock_client_hello[7] = ((handshake_len >> 16) & 0xff) as u8;
        mock_client_hello[8] = ((handshake_len >> 8) & 0xff) as u8;
        mock_client_hello[9] = (handshake_len & 0xff) as u8;
        
        let ctx = HelloPolicyContext {
            tls12: true,
            tls13: true,
            is_quic: false,
            sni: &[],
        };
        
        let result = policy.reality_inject_clienthello(&mock_client_hello, &ctx);
        assert!(result.is_some());
        
        let modified = result.unwrap();
        // 验证session_id长度被正确设置
        assert_eq!(modified[5 + 4 + 2 + 32], b"test_reality_token_123456".len() as u8);
        
        // 验证token被正确注入
        let session_id_start = 5 + 4 + 2 + 32 + 1;
        let session_id_end = session_id_start + b"test_reality_token_123456".len();
        assert_eq!(&modified[session_id_start..session_id_end], b"test_reality_token_123456");
    }

    #[test]
    fn test_cipher_suite_reordering() {
        let policy = RealityHelloPolicy::new();
        let current = vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_128_GCM_SHA256,
            CipherSuite::TLS13_AES_256_GCM_SHA384,
        ];
        
        let ctx = HelloPolicyContext {
            tls12: true,
            tls13: true,
            is_quic: false,
            sni: &[],
        };
        
        let result = policy.cipher_suites(&current, &ctx);
        assert!(result.is_some());
        
        let reordered = result.unwrap();
        // 验证TLS 1.3 cipher suites被优先排序
        assert_eq!(reordered[0], CipherSuite::TLS13_AES_128_GCM_SHA256);
        assert_eq!(reordered[2], CipherSuite::TLS13_AES_256_GCM_SHA384);
    }
}