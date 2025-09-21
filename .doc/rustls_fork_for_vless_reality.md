# 为 VLESS REALITY 需求 Fork 官方 rustls 的动机与实现要点（参考 craftls）

> 目标读者：准备在最新 rustls（0.23.x）上实现“可定制 ClientHello 指纹/握手细节”的工程师；不破坏 tokio-rustls 0.26.x、reqwest、tokio-tungstenite 等生态的既有兼容性。

## 1. 为什么需要 Fork rustls

VLESS REALITY 的核心诉求：
- 在“对外表现”为标准 TLS（与 decoy 站点/域名建立 TLS）同时，客户端需要“强可定制的 ClientHello 指纹”（扩展顺序、CipherSuites/Groups/SignAlgs 的次序、Grease、Padding 长度与位置、ALPN 是否携带、SNI/Session 行为等），以逼真模拟主流浏览器/系统栈，从而提升抗识别能力。
- 官方 rustls 以“协议合规、最小表面积、安全默认”为最高优先级，当前公开 API 对 ClientHello 细节的控制粒度有限（多依赖内部策略），难以精确复刻浏览器级指纹。
- craftls 证明了“可编排 ClientHello 字节级细节”的工程可行性，但其生态兼容性与维护路线与现有项目依赖的 rustls/tokio-rustls 并不完全一致。

因此，fork rustls 的目标是：
- 保持 rustls 0.23.x 的对外 API 与默认行为不变（确保生态“无感”）。
- 仅在“显式启用”的路径上，引入“可编排的 ClientHello 构造接口”，以支持 REALITY 所需的指纹策略；默认不开启时与上游完全一致。

## 2. 与 craftls 的对照与借鉴点

craftls 提供：
- 可编排的 ClientHello Builder：允许控制扩展顺序、填充、随机化策略。
- 指纹模板（Chrome/Firefox/iOS/Edge/Android 等）与可微调参数（例如 Padding 长度、ALPN 列表）。
- 明确的“字节级黄金用例”测试，验证产出 ClientHello 与目标模板完全一致。

在 fork 的 rustls 中应借鉴：
- 以“Builder/Policy + Preset + 可覆盖策略”的组合，生成 ClientHello。
- 以“黄金样例测试”固化输出，避免回归。

## 3. 设计原则（兼容优先）

- API 兼容：不改动现有公有类型签名（ClientConfig/ClientConnection 等）；新增接口置于“独立模块/特性”但默认不开。
- 运行时开关优于 Cargo feature：避免 feature 并集带来的全局副作用；仅当上层显式配置时，才走自定义 ClientHello 路径。
- 安全默认：若未配置或配置非法，回退到上游默认策略；证书验证流程保持不变（webpki/平台验证），SNI/主机名校验不放松。

## 4. 建议的 API 形态

新增模块：`rustls::client::hello_craft`（命名可调整），暴露以下能力：
- 指纹模板：`FingerprintProfile`（ChromeLatest、FirefoxLatest、iOS17、Android13、Custom 等）。
- 可选策略：
  - 扩展顺序/子扩展顺序（Extensions/ALPS/ALPN/Padding/KeyShare/SupportedVersions/SignatureAlgorithms/SupportedGroups 等）。
  - CipherSuites/Groups/SignatureAlgorithms 的次序与子集。
  - GREASE 策略（开/关、位宽）与 KeyShare 个数。
  - Padding 策略（定长/自适应/关闭，位置靠前/靠后）。
  - ALPN（携带与否、顺序、http/1.1 vs h2）。
  - Session/PSK/0-RTT 策略（默认禁用 0‑RTT；允许关闭 SessionTicket）。

- 运行时注入点：在 `ClientConfig` 上新增可选字段 `hello_policy: Option<Arc<dyn HelloPolicy>>`。

示例（上层调用）：

```rust
let mut cfg = rustls::ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();

cfg.hello_policy = Some(Arc::new(
    HelloPolicy::from_preset(FingerprintPreset::ChromeLatest)
        .with_padding(PaddingStrategy::Adaptive)
        .with_grease(true)
        .with_alpn(vec!["h2", "http/1.1"])
));
```

> 注意：若 `hello_policy` 为 `None`，则完全按上游既有路径构建 ClientHello（零差异）。
## 4.1 注入点与优先级规则（问答确认）

- ALPN 优先级（与 ClientConfig.alpn_protocols 的关系）
  - 采用 C 策略：若 HelloPolicy 显式指定 ALPN，则覆盖 ClientConfig.alpn_protocols；否则沿用 ClientConfig 的配置。
  - 建议对每个可控项采用“三态”语义：Inherit（默认）/Override/Filter。
    - Inherit：完全沿用 ClientConfig/默认；
    - Override：由策略给出完整列表并覆盖；
    - Filter：在现有列表上按策略顺序/子集进行重排与过滤，不新增越权项。
- CipherSuites/Groups/SignatureAlgorithms 的覆盖
  - 默认 Inherit；允许策略选择 Override 或 Filter。
  - 安全边界不变：不允许策略启用被上游标记为不安全/禁用的套件。
- TLS 版本范围
  - 第一阶段仅对 TLS 1.3 的 ClientHello 构造提供可编排；TLS 1.2 路径保持上游默认策略不变。
  - 后续可在不影响默认行为的前提下扩展 TLS 1.2 的可编排能力。
- 0‑RTT / Session / PSK
  - 策略启用路径下：默认关闭 0‑RTT；
  - SessionTicket：允许策略显式关闭；
  - PSK：保持上游默认，除非策略显式禁用。
- GREASE / KeyShare 细节
  - 严格随 FingerprintPreset（浏览器行为）执行：GREASE 的宽度与位置、KeyShare 的个数与顺序均以 preset 为准；
  - 仅当策略显式覆盖时才偏离 preset；
  - 为测试可复现性，提供可选的确定性随机种子（不影响默认安全随机）。
  - KeyShare 多份/顺序设置示例：

    ```rust
    use rustls::enums::NamedGroup;
    use rustls::client::hello_policy::BrowserLikePolicy;
    use alloc::sync::Arc;

    let policy = BrowserLikePolicy::chrome_latest()
        .with_preferred_key_shares(vec![NamedGroup::X25519, NamedGroup::secp256r1()]);
    cfg.hello_policy = Some(Arc::new(policy));
    ```

    说明：若服务端通过 HRR 指定特定组，后续 ClientHello 仅保留该组的 KeyShare；默认 Chrome 预设仍只发送 X25519。

- 预置指纹的最小集
  - 里程碑确认：先提交“最小可行 PR”（只引入 HelloPolicy 框架 + DefaultHelloPolicy）；
  - 随后加入 BrowserLikePolicy + ChromeLatest preset 与黄金样例测试（ChromeLatest 作为首个 preset 已确认）。
- 黄金样例测试数据来源
  - 优先使用稳定公开的浏览器指纹模板（参考 craftls 的 ChromeLatest）；
  - 如无权威 hex，可用我们基于 preset 生成的 ClientHello，与常见服务（如 Cloudflare）实测成功后冻结为黄金样例；
  - 样例建议落库：tests/data/hello/chrome_latest_exts.hex（扩展区段），并在单测中进行字节级对比；必要时使用固定的 ext_seed 以保证可复现。

## 4.2 现有 fork（feat/hello-policy-0.23x）能力评估

基于提交 7d88fd5f（更新至 2025-09-21；HelloPolicy 框架 + DefaultHelloPolicy + BrowserLikePolicy/ChromeLatest，含 ALPN 控制、TLS 1.3 cipher suite 偏好、扩展顺序的确定性 seed 等），当前状态：

- 优点（已具备）
  - 运行时注入的 HelloPolicy 框架，默认零差异（DefaultHelloPolicy）。
  - BrowserLikePolicy + ChromeLatest 预设；
  - 可控制：
    - ALPN 顺序/覆盖（与 4.1 的优先级策略一致，重试路径亦保持一致）。
    - TLS 1.3 cipher suite 偏好顺序。
    - SupportedGroups / SignatureAlgorithms 顺序与子集。
    - 列表级 GREASE 注入（SupportedGroups/SignatureSchemes，支持 head/tail、数量 0/1）。
    - 扩展顺序的确定性（seed），并支持“连续扩展块”基于锚点的插入策略。
    - TLS1.3 Padding：长度与精确定位（Before/After/Tail/Default），无显式连续块时采用安全回退（Padding 紧贴 SupportedVersions 前）。
  - 回归与集成测试通过（默认路径零差异）。

- 不足/待增强
  - GREASE 更细粒度：
    - ✅ 列表级 GREASE (SupportedGroups/SignatureSchemes) - 已实现
    - ⚠️ KeyShare GREASE - 需要修改 rustls 核心结构，暂不实现
    - ⚠️ Extension-type GREASE - 需要修改 rustls 核心编码逻辑，暂不实现
    - ⚠️ GREASE extension values - 需要修改 rustls 核心编码逻辑，暂不实现
  - TLS 1.2 可编排能力：仍未提供（可视需求规划）。
  - 测试覆盖深化：不同 ext_seed 的稳定性、GREASE 位置/数量断言、更复杂重试路径的字节级断言。
  - Lints 与文档细化：清理非功能性 lints、补充 README 链接与示例。

- 结论
  - 用于“PoC/受控环境”以缓解现实问题：可用（TLS 1.3 + ALPN/cipher + 扩展顺序/填充定位稳定）。
  - 若追求“更强对抗 DPI/更广覆盖”的生产化：优先补齐 KeyShare 多份、黄金样例（完整 ClientHello）、GREASE 细粒度与测试深化。

## 4.3 HelloPolicy 实现状态详解

### ✅ 已完成功能

#### 核心框架
- **HelloPolicy trait** (`client/hello_policy.rs`)：完整的运行时可插拔策略系统
  - 定义了完整的策略接口，支持 ClientHello 各个方面的定制
  - 通过 `ClientConfig.hello_policy` 字段注入，类型为 `Option<Arc<dyn HelloPolicy>>`
- **DefaultHelloPolicy**：零开销的默认实现
  - 所有方法返回默认值，确保未设置策略时行为与上游完全一致
- **BrowserLikePolicy**：Chrome 预设与定制方法
  - `chrome_latest()` 静态方法提供开箱即用的 Chrome 指纹
  - 丰富的 builder 方法支持细粒度定制

#### 协议控制
- **ALPN 支持**（`alpn()` 方法）：
  - `AlpnDecision::Inherit`：使用配置中的默认 ALPN
  - `AlpnDecision::Override`：完全替换 ALPN 列表
  - `AlpnDecision::Filter`：基于顺序过滤现有列表
- **Cipher Suites**（`cipher_suites()` 方法）：控制密码套件顺序和选择
- **Supported Groups**（`supported_groups()` 方法）：椭圆曲线组的顺序和过滤
- **Signature Algorithms**（`signature_algorithms()` 方法）：签名方案偏好定制
- **扩展顺序**（`extension_order_seed()` 方法）：确定性种子支持

#### 会话与密钥交换
- **多 KeyShare 支持**（`preferred_key_share_groups()` 方法）：
  - 支持同时提供多个组的 KeyShare
  - 在 `initial_key_shares()` 中实现（`client/tls13.rs`）
  - HRR 重试路径正确处理
- **PSK/0-RTT/SessionTicket 控制**：
  - `disable_psk()`：禁用预共享密钥
  - `disable_early_data()`：禁用 0-RTT 早期数据
  - `disable_session_ticket()`：禁用会话票据

#### TLS 1.3 特性
- **Padding 扩展**（`tls13_padding_len()` 和 `tls13_padding_position()` 方法）：
  - 长度控制：0-65535 字节
  - 位置控制：Before/After/Tail/Default
  - 在 `emit_client_hello_for_retry()` 中实现（`client/hs.rs`）
- **连续扩展块**：
  - 通过 `contiguous_extensions` 字段支持锚点插入
  - 保证相关扩展的连续性

#### 测试钩子
- **fixed_client_random**：用于黄金样例的固定随机数
- **force_empty_session_id**：强制空会话 ID

### ⚠️ 部分完成

#### GREASE 实现
- ✅ **列表级 GREASE**（已在 `client/hs.rs` 中实现）：
  ```rust
  // 在 emit_client_hello_for_retry() 中
  if policy.grease_lists(&ctx) {
      let grease = choose_grease(seed);
      // 插入到 SupportedGroups 和 SignatureSchemes
  }
  ```
- ❌ **KeyShare GREASE**：未实现（需要生成假的 KeyShare）
- ❌ **Extension-type GREASE**：未实现（需要注入完整的假扩展）
- ❌ **GREASE extension values**：未实现（需要为扩展添加 GREASE 值）

#### 黄金样例测试
- ✅ **扩展段 hex**：`tests/data/hello/chrome_latest_exts.hex`
- ⚠️ **完整 ClientHello hex**：占位符存在，但实际生成受构建问题影响
- ⚠️ **字节级验证**：需要实际的 hex 数据

### ❌ 未实现功能

#### 高级 GREASE 特性（需要深度协议修改）

1. **KeyShare GREASE**
   - 需要生成带 GREASE 组的假密钥共享
   - 需要修改密钥共享生成逻辑
   - 与 HRR 重试路径的复杂交互

2. **Extension-type GREASE**
   - 需要注入完整的假扩展
   - 需要谨慎放置以避免协议违规
   - 比列表 GREASE 更复杂

3. **GREASE extension values**
   - 需要向各种扩展负载添加 GREASE 值
   - 每种扩展类型有不同的约束

### 使用示例

#### 基本用法
```rust
use rustls::client::hello_policy::BrowserLikePolicy;
use std::sync::Arc;

// 创建 Chrome 风格的 ClientHello
let mut config = ClientConfig::builder()
    .with_root_certificates(roots)
    .with_no_client_auth();

// 应用 Chrome 预设
config.hello_policy = Some(Arc::new(BrowserLikePolicy::chrome_latest()));
```

#### 高级定制
```rust
let policy = BrowserLikePolicy::chrome_latest()
    // 配置 GREASE
    .with_grease_lists(true)
    .with_grease_position(ListPosition::Head)
    .with_grease_count(1)

    // 配置 Padding
    .with_padding_len(Some(256))
    .with_padding_position(PaddingPosition::Before(ExtensionType::SupportedVersions))

    // 多个 KeyShare
    .with_preferred_key_shares(vec![
        NamedGroup::X25519,
        NamedGroup::secp256r1,
    ])

    // 测试用：固定随机数
    .with_fixed_client_random([0u8; 32])
    .with_force_empty_session_id(true);

config.hello_policy = Some(Arc::new(policy));
```

#### 自定义策略实现
```rust
#[derive(Debug)]
struct MyCustomPolicy;

impl HelloPolicy for MyCustomPolicy {
    fn alpn(&self, current: &[Vec<u8>], ctx: &HelloPolicyContext<'_>) -> AlpnDecision {
        if ctx.tls13 {
            AlpnDecision::Override(vec![b"h3".to_vec()])
        } else {
            AlpnDecision::Inherit
        }
    }

    // 其他方法使用默认实现...
}
```

### 代码集成点

#### 关键文件
- `rustls/src/client/hello_policy.rs`：HelloPolicy trait 和实现
- `rustls/src/client/hs.rs`：握手逻辑中的集成点
- `rustls/src/client/tls13.rs`：TLS 1.3 特定功能
- `rustls/src/client/test.rs`：策略应用测试
- `rustls/src/client/test_grease.rs`：GREASE 特定测试

#### 主要集成点
1. **ClientHelloInput::new()**：ALPN 和扩展种子策略应用
2. **emit_client_hello_for_retry()**：主要的 ClientHello 构造，包含策略钩子
3. **prepare_resumption()**：PSK 和早期数据策略控制
4. **initial_key_shares()**：多 KeyShare 支持

### 生产就绪评估

#### 当前状态：**开发/PoC 就绪** ✅
当前实现适用于：
- 开发和测试环境
- 概念验证部署
- 与已知服务器的受控生产使用

#### 现在可用的功能：
- 基本浏览器指纹模拟（Chrome 预设）
- ALPN、密码套件和扩展定制
- 用于反指纹识别的列表级 GREASE
- 多密钥共享支持
- 确定性测试能力

#### 完整生产化缺失的部分：
1. **完整的 GREASE 实现** - 仅完成列表级 GREASE
2. **完整的黄金样例验证** - 构建问题阻碍完整测试
3. **广泛的互操作性测试** - 未针对各种服务器测试
4. **额外的浏览器预设** - 仅实现了 Chrome

### 建议

#### 立即使用：
当前实现可用于 VLESS REALITY，但有以下限制：
- 使用列表级 GREASE（对大多数 DPI 规避足够）
- Chrome 预设提供合理的浏览器模拟
- 多密钥共享正常工作

#### 完整生产部署：
考虑以下增强：
1. 如果面临高级 DPI，实现 KeyShare GREASE
2. 添加更多浏览器预设（Firefox、Safari）
3. 解决构建问题后完成黄金样例测试
4. 添加全面的重试路径测试

### 构建问题说明
Windows 上的 aws-lc-rs NASM 依赖阻碍了部分测试。选项：
1. 使用 Linux/macOS 进行开发
2. 在 Windows 上安装 NASM
3. 使用 Docker 获得一致的构建环境
4. 修改 Cargo.toml 使用仅 ring 配置

### 测试命令

```bash
# 运行所有 HelloPolicy 相关测试
cargo test --lib client::test hello_policy
cargo test --lib client::test_grease

# 生成完整 ClientHello 黄金样例
cargo test --lib client::test::print_chrome_latest_full_clienthello_hex -- --ignored --nocapture

# 或使用示例程序
cargo run --example generate_clienthello > clienthello.hex

# 验证黄金样例
cargo test --lib client::test hello_policy_chrome_latest_exts_golden_matches
```


说明：上述“待补充/增强”将分阶段落地，优先推进“完整 ClientHello 的黄金样例 + KeyShare 多份/更细粒度 GREASE + 测试深化”。


## 5. 代码落点（以 0.23.x 为基线）

- 客户端握手路径定位：`client::hs`/`client::common` 中 ClientHello 构造处（将当前内部“固定策略”改为“策略接口 + 默认实现”）。
- 定义 `HelloPolicy` trait：接收“标准化参数结构”（Cipher/Group/SignAlgs 列表、扩展集合、是否携带 ALPN/SNI、Padding 策略等），输出“已排序/已决定的构造指令”。
- 默认实现 `DefaultHelloPolicy`：严格复刻 upstream 逻辑（字节级等价）。
- 预置 `BrowserLikePolicy`：按 preset 生成参数，并允许微调。
- 与 `crypto::ring`/`aws-lc-rs` 无耦合；仅影响握手构造阶段，不触碰加解密实现。
- tokio-rustls 无需改动；其基于 `ClientConfig/Connection` 的使用不变。

## 6. 证书与安全

- 证书验证与主机名校验逻辑保持上游默认；`hello_policy` 仅影响 ClientHello 的“外形”，不影响验证决策。
- 提供“平台验证（platform verifier）”的兼容开关（复用 hickory 等生态用法），但默认关闭。
- 禁止默认启用“宽松模式”（例如跳过验证、忽略主机名不匹配）。

## 7. 测试策略

- 回归测试：复用上游所有测试，确保 fork 在默认路径下 100% 通过。
- 指纹黄金测试：
  - 为每个 `FingerprintPreset` 准备“预期 ClientHello 十六进制”样例，比对字节级一致性。
  - 单元测试覆盖：扩展顺序、Grease 注入、Padding 长度/位置、ALPN 序列、Cipher/Group/SignAlgs 顺序。
- 互通性测试：
  - 与常见服务器（Nginx/Cloudflare/Apache/各 CDN）的握手通过率。
  - 与 `tokio-rustls`、`reqwest(hyper-rustls)`、`tokio-tungstenite` 的集成握手。
- 负面测试：关闭/缺失 SNI、超长/异常 Padding、无 ALPN 等边界条件。

## 8. 性能与稳定性

- 构造策略应常量时间/低分配，允许缓存常见 preset 的“指令表”。
- 对默认路径零开销（`hello_policy: None` 时不触发额外逻辑）。
- 提供 `RUSTLS_LOG=trace` 诊断：仅输出“策略选择摘要”，不泄露敏感密钥材料。

## 9. 集成与回滚

- 工作区统一替换：在上层仓库用 `[patch.crates-io]` 将 `rustls` 指向 fork 分支；fork 的 `Cargo.toml` 版本保持 `0.23.32`， API 完全兼容。
- 仅在 VLESS REALITY 代码路径上设置 `hello_policy`；普通路径不设置，保持默认。
- 回滚：移除 `[patch.crates-io]` 即可恢复官方 rustls。

## 10. 与 VLESS REALITY 的接口契约（客户端侧）

- REALITY 相关参数（如公钥/短 ID/指纹 preset/ALPN 策略/是否 session/是否 0‑RTT/是否 padding）由上层 VLESS 配置翻译为 `HelloPolicy`。
- SNI：必须为 decoy 域名；证书验证针对该 SNI 进行。
- ALPN：按目标流量类型选择（常见为 ["h2","http/1.1"]），或按指纹 preset 固定。
- KeyShare/Grease：遵循浏览器模板；除非上层明确覆盖。

## 11. 风险与注意事项

- 协议回归风险：任何对默认路径的改变都可能影响整个生态；务必用黄金测试与互通测试兜底。
- 安全边界：不要把“放松验证/关闭验证”绑在此功能上；REALITY 只需要“外形可定制”。
- 维护成本：跟进上游更新，保持最小差异；推荐将策略实现集中在单文件/模块，便于 rebase。

## 12. 里程碑

1) 提交最小可行 PR：新增 `HelloPolicy` 框架与 `DefaultHelloPolicy`，不启用任何新 preset。
2) 加入 `BrowserLikePolicy` 与 `ChromeLatest` preset + 黄金测试。
3) 加入 Padding/GREASE/ALPN 可调；补充 Firefox/iOS preset。
4) 集成到代理核心（仅 VLESS REALITY 路径启用），完成端到端测试。
5) 文档与示例完善。

---

附：与上层调用的对接建议（示例）

```rust
// 在 VLESS REALITY 路径启用自定义指纹；其他路径不设置 hello_policy。
let cfg = make_default_rustls_client_config();
let cfg = cfg.with_hello_policy(
    HelloPolicy::from_preset(FingerprintPreset::ChromeLatest)
        .with_padding(PaddingStrategy::Adaptive)
        .with_grease(true)
        .with_alpn(vec!["h2", "http/1.1"])
);
```

> 以上仅为 API 形态示意，实际实现需保持与 rustls 现有类型/构造器的兼容与风格一致。
