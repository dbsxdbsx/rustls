//! REALITY协议使用示例
//!
//! 这个示例展示如何在rustls中使用HelloPolicy来支持VLESS REALITY协议，
//! 包括如何向ClientHello的legacy_session_id字段注入AEAD加密认证令牌。

use std::sync::Arc;
use rustls::client::{ClientConfig, RealityHelloPolicy};
use rustls::crypto::aws_lc_rs;

#[cfg(feature = "reality-crypto")]
use rustls::reality_crypto::{RealityConfig, RealityCrypto};

/// 演示如何创建支持REALITY协议的ClientConfig
fn create_reality_client_config() -> Result<ClientConfig, Box<dyn std::error::Error>> {
    // 1. 创建REALITY token (通常这是通过AEAD加密得到的)
    // 在实际应用中，这个token是通过以下步骤生成的：
    // - 使用X25519进行密钥交换
    // - 通过HKDF扩展共享密钥
    // - 使用AES-256-GCM对用户认证信息进行AEAD加密
    let reality_token = b"example_reality_token_123456".to_vec(); // 32字节以内

    // 2. 创建RealityHelloPolicy
    let reality_policy = RealityHelloPolicy::new()
        .with_reality_token(reality_token)
        .with_grease(true); // 启用GREASE来模仿浏览器行为

    // 3. 创建ClientConfig并设置HelloPolicy
    let config = ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth()
        .with_hello_policy(Arc::new(reality_policy));

    Ok(config)
}

/// 使用真正的REALITY加密实现生成token
#[cfg(feature = "reality-crypto")]
fn generate_reality_token_proper(
    user_id: &[u8],
    server_public_key: &[u8; 32],
    client_private_key: &[u8; 32],
    server_name: &str
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // 创建REALITY配置
    let config = RealityConfig::new(
        user_id.to_vec(),
        *server_public_key,
        *client_private_key,
        server_name.to_string(),
    );

    // 创建加密器并生成令牌
    let crypto = RealityCrypto::new(config);
    let token = crypto.generate_token()?;

    Ok(token)
}

/// 简化的REALITY token生成过程（向后兼容）
fn generate_reality_token_simple(
    user_id: &[u8],
    server_public_key: &[u8],
    client_private_key: &[u8]
) -> Vec<u8> {
    // 注意：这是一个简化的示例，实际的REALITY协议需要：
    // 1. X25519密钥交换
    // 2. HKDF密钥派生
    // 3. AES-256-GCM AEAD加密

    let mut token = Vec::with_capacity(32);
    token.extend_from_slice(user_id);

    // 简化的"加密"过程（实际应该使用真正的AEAD）
    for (i, byte) in token.iter_mut().enumerate() {
        *byte ^= server_public_key[i % server_public_key.len()];
        *byte ^= client_private_key[i % client_private_key.len()];
    }

    // 确保token长度不超过32字节（legacy_session_id的最大长度）
    token.truncate(32);
    token
}

/// 完整的REALITY客户端使用示例
fn reality_client_example() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 模拟密钥材料（在实际应用中这些来自VLESS配置）
    let user_id = b"user123456789012"; // 16字节用户ID
    let server_public_key = b"server_pubkey_32_bytes_example12"; // 32字节服务器公钥
    let client_private_key = b"client_privkey_32_bytes_example1"; // 32字节客户端私钥
    let server_name = "example.com";

    // 2. 生成REALITY认证token
    #[cfg(feature = "reality-crypto")]
    let reality_token = {
        println!("🔐 Using proper REALITY crypto implementation...");
        let server_pub_key: [u8; 32] = server_public_key[..32].try_into().unwrap();
        let client_priv_key: [u8; 32] = client_private_key[..32].try_into().unwrap();
        generate_reality_token_proper(user_id, &server_pub_key, &client_priv_key, server_name)?
    };

    #[cfg(not(feature = "reality-crypto"))]
    let reality_token = {
        println!("⚠️  Using simplified token generation (reality-crypto feature not enabled)");
        generate_reality_token_simple(user_id, server_public_key, client_private_key)
    };

    println!("Generated REALITY token: {} bytes", reality_token.len());
    println!("Token (hex): {}", hex::encode(&reality_token));

    // 3. 创建支持REALITY的ClientConfig
    #[cfg(feature = "reality-crypto")]
    let reality_policy = {
        // 使用动态令牌生成
        let config = RealityConfig::new(
            user_id.to_vec(),
            server_public_key[..32].try_into().unwrap(),
            client_private_key[..32].try_into().unwrap(),
            server_name.to_string(),
        );

        RealityHelloPolicy::new()
            .with_crypto_config(config)
            .with_grease(true)
            .with_cipher_order(vec![
                rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
                rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
                rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
            ])
    };

    #[cfg(not(feature = "reality-crypto"))]
    let reality_policy = RealityHelloPolicy::new()
        .with_reality_token(reality_token)
        .with_grease(true)
        .with_cipher_order(vec![
            rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
            rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
        ]);

    let config = ClientConfig::builder_with_provider(aws_lc_rs::default_provider().into())
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth()
        .with_hello_policy(Arc::new(reality_policy));

    println!("✅ REALITY ClientConfig created successfully!");
    println!("   - REALITY token will be injected into ClientHello legacy_session_id");
    println!("   - Chrome-like cipher suite ordering enabled");
    println!("   - GREASE enabled for better fingerprint mimicking");

    #[cfg(feature = "reality-crypto")]
    println!("   - Dynamic token generation enabled");

    // 4. 现在可以使用这个config创建ClientConnection
    // let client_conn = rustls::ClientConnection::new(
    //     Arc::new(config),
    //     server_name.try_into()?
    // )?;

    Ok(())
}

fn main() {
    println!("🔒 Rustls REALITY Protocol Support Example");
    println!("==========================================");

    match reality_client_example() {
        Ok(()) => {
            println!("\n✅ Example completed successfully!");
            println!("\n📝 Integration Notes:");
            println!("   1. This demonstrates the HelloPolicy approach for REALITY support");
            println!("   2. The token injection happens automatically during ClientHello construction");

            #[cfg(feature = "reality-crypto")]
            {
                println!("   3. ✅ Proper X25519+HKDF+AES-256-GCM crypto implementation included");
                println!("   4. ✅ Dynamic token generation with crypto configuration");
                println!("   5. ✅ Server-side token verification support");
            }

            #[cfg(not(feature = "reality-crypto"))]
            {
                println!("   3. ⚠️  Using simplified crypto (enable 'reality-crypto' feature for full implementation)");
            }

            println!("   6. The forked rustls now supports byte-level ClientHello customization");
            println!("   7. Chrome-like fingerprint mimicking with GREASE support");
        }
        Err(e) => {
            eprintln!("❌ Error: {}", e);
            std::process::exit(1);
        }
    }
}

// 简化的hex编码功能（避免额外依赖）
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}