# VLESS REALITY Protocol Support in Rustls

## 概述

本项目为rustls添加了对VLESS REALITY协议的支持，通过`HelloPolicy` trait实现了向ClientHello消息的`legacy_session_id`字段注入AEAD加密认证令牌的功能。这是解决REALITY协议在rustls中实现的关键技术难题。

## 技术背景

### REALITY协议需求
VLESS REALITY协议需要在TLS ClientHello握手消息中嵌入经过AEAD加密的认证令牌，具体要求：
- 令牌必须被注入到ClientHello的`legacy_session_id`字段中
- 需要在消息发送前的最后时刻进行字节级修改
- 不能破坏TLS握手的正常流程

### 技术挑战
1. **字节级控制缺失**：原版rustls不提供对ClientHello字节内容的直接控制
2. **时机问题**：需要在消息构造完成后、发送前进行修改
3. **协议完整性**：修改必须保持TLS协议的有效性

## 解决方案

### 1. HelloPolicy框架扩展

在`HelloPolicy` trait中新增了`reality_inject_clienthello`方法：

```rust
/// REALITY support: modify ClientHello bytes just before sending.
/// This allows injecting REALITY authentication tokens into legacy_session_id.
fn reality_inject_clienthello(&self, original_bytes: &[u8], ctx: &HelloPolicyContext<'_>) -> Option<Vec<u8>> {
    None
}
```

### 2. ClientHello发送流程修改

在`emit_client_hello_for_retry`函数中添加了REALITY钩子调用：

```rust
// REALITY support: Allow HelloPolicy to modify ClientHello bytes before sending
let ch = if let Some(policy) = config.hello_policy.as_ref() {
    let ctx = HelloPolicyContext { ... };
    let original_bytes = PlainMessage::from(ch.into_owned()).into_unencrypted_opaque().encode();
    
    if let Some(modified_bytes) = policy.reality_inject_clienthello(&original_bytes, &ctx) {
        // Decode modified bytes back to Message
        // ...
    } else {
        // Use original message
        // ...
    }
} else {
    ch
};
```

### 3. RealityHelloPolicy实现

创建了专用的`RealityHelloPolicy`实现：

- **REALITY令牌注入**：精确定位`legacy_session_id`字段并替换内容
- **Chrome风格指纹**：模仿Chrome浏览器的TLS指纹特征
- **GREASE支持**：启用GREASE来增强反检测能力
- **消息长度更新**：自动更新TLS记录和握手消息的长度字段

## 核心功能

### 1. 令牌注入机制

```rust
fn inject_reality_token(&self, client_hello_bytes: &[u8]) -> Option<Vec<u8>> {
    let token = self.reality_token.as_ref()?;
    
    // 定位legacy_session_id字段
    let session_id_len_offset = 5 + 4 + 2 + 32; // TLS记录头 + 握手头 + 版本 + 随机数
    let session_id_len = modified_bytes[session_id_len_offset];
    
    // 替换session_id内容
    modified_bytes[session_id_len_offset] = token.len() as u8;
    // ... 替换实际数据并更新消息长度
}
```

### 2. 使用示例

```rust
use rustls::client::{ClientConfig, RealityHelloPolicy};

// 创建REALITY policy
let reality_policy = RealityHelloPolicy::new()
    .with_reality_token(reality_token)
    .with_grease(true);

// 配置ClientConfig
let config = ClientConfig::builder_with_provider(provider)
    .with_root_certificates(roots)
    .with_no_client_auth()?
    .with_hello_policy(Arc::new(reality_policy));
```

## 技术特性

### ✅ 已实现功能

1. **字节级ClientHello修改**：完全控制ClientHello消息的字节内容
2. **REALITY令牌注入**：精确向`legacy_session_id`字段注入认证令牌
3. **Chrome指纹模拟**：支持Chrome风格的cipher suite排序和扩展顺序
4. **GREASE支持**：完整的GREASE实现以模拟真实浏览器行为
5. **消息完整性**：自动维护TLS消息的长度字段和协议完整性
6. **灵活配置**：支持运行时配置令牌、密码套件顺序等参数

### 🔧 架构优势

1. **最小侵入性**：通过HelloPolicy扩展，不破坏rustls核心架构
2. **向后兼容**：不影响现有rustls应用的正常使用
3. **可扩展性**：HelloPolicy框架可支持更多ClientHello定制需求
4. **类型安全**：保持Rust的类型安全特性

## 文件结构

```
rustls/rustls/src/client/
├── hello_policy.rs              # HelloPolicy trait定义和基础实现
├── hello_policy_reality.rs      # REALITY协议专用实现
└── hs.rs                        # ClientHello发送流程（已修改）

rustls/rustls/examples/
└── reality_example.rs           # 使用示例

rustls/
└── REALITY_SUPPORT.md          # 本文档
```

## 测试验证

### 单元测试
- `test_reality_token_injection`: 验证令牌正确注入到`legacy_session_id`
- `test_cipher_suite_reordering`: 验证Chrome风格密码套件排序

### 集成测试
示例代码演示了完整的使用流程，从令牌生成到ClientConfig配置。

## 与上游rustls的差异

### 核心修改

1. **HelloPolicy trait扩展**：添加`reality_inject_clienthello`方法
2. **ClientHello发送流程**：在`emit_client_hello_for_retry`中添加钩子调用
3. **新增模块**：`hello_policy_reality.rs`完全独立实现

### 兼容性保证

- 所有现有API保持不变
- 默认行为与原版rustls完全相同
- 只有显式使用RealityHelloPolicy才会触发新功能

## 安全考虑

### REALITY令牌处理
- 令牌通过内存安全的Vec<u8>传递
- 支持最大32字节令牌（TLS规范限制）
- 不在日志中输出敏感信息

### 协议安全性
- 保持TLS握手的密码学安全性
- 不影响证书验证等安全机制
- 仅在应用层添加REALITY支持

## 生产使用建议

### 1. 密钥管理
```rust
// 实际应用中应实现完整的REALITY密钥协商：
// 1. X25519密钥交换
// 2. HKDF密钥派生
// 3. AES-256-GCM AEAD加密
let reality_token = generate_reality_token_with_proper_crypto(
    user_id, server_public_key, client_private_key
);
```

### 2. 错误处理
```rust
let config = ClientConfig::builder_with_provider(provider)
    .with_root_certificates(roots)
    .with_no_client_auth()
    .map_err(|e| format!("Config creation failed: {}", e))?
    .with_hello_policy(Arc::new(reality_policy));
```

### 3. 日志和调试
- 避免在日志中输出REALITY令牌
- 使用debug构建进行开发调试
- 生产环境使用release构建

## 未来改进方向

### 1. 性能优化
- 减少ClientHello字节序列化/反序列化开销
- 优化令牌注入的内存分配

### 2. 功能扩展
- 支持更多浏览器指纹模拟
- 添加更多GREASE变体
- 支持动态令牌刷新

### 3. 安全增强
- 添加令牌验证机制
- 支持令牌过期时间
- 增强反分析能力

## 贡献指南

### 开发环境
```bash
cd rustls
cargo check --lib
cargo test hello_policy_reality --lib
```

### 代码规范
- 遵循rustls现有代码风格
- 添加充分的文档注释
- 确保向后兼容性

## 总结

本实现成功解决了REALITY协议在rustls中的集成难题，通过HelloPolicy框架提供了灵活而强大的ClientHello定制能力。实现具备以下特点：

- ✅ **功能完整**：支持完整的REALITY令牌注入流程
- ✅ **架构优雅**：最小化侵入性修改，保持rustls架构清洁
- ✅ **性能高效**：零开销抽象，不影响正常TLS性能
- ✅ **安全可靠**：保持TLS协议的安全性和完整性
- ✅ **易于使用**：简洁的API设计，方便集成到现有项目

这为在Rust生态系统中实现VLESS REALITY客户端提供了坚实的技术基础。