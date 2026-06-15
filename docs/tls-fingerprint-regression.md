# TLS 指纹抓包回归测试方案

本文定义 trojan-rs 的 TLS 指纹回归方法，并分析是否能够通过伪装页采集真实浏览器的 TLS 指纹，再据此调整 BoringSSL 配置。

## 1. 目标与非目标

测试目标：

- TLS、WebSocket、依赖和构建工具链变更后，发现 ClientHello、ServerHello、ALPN 和握手行为的意外变化；
- 保证 TLS 层声明与后续应用协议一致；
- 区分安全回归、协议回归、预期的 BoringSSL 升级变化和操作系统网络栈差异；
- 生成可审查、可复现的结构化差异，而不是只保存一个 JA4 字符串。

非目标：

- 不承诺不可识别或绕过流量分类；
- 不以复制某个 Chrome 版本的单次抓包为验收标准；
- 不把 IP 分片、TCP 时序或公网路径抖动误判为 TLS 库回归；
- 不在生产环境默认记录原始 ClientHello、IP、SNI、会话票据或用户标识。

## 2. 当前实现的预期基线

当前客户端由 `boring 5.1.0`、`boring-sys 5.1.0` 和 `tokio-boring 5.0.0` 构建。代码只显式设置最低 TLS 1.2、信任根、SNI、传输相关 ALPN，以及可选的 TLS 1.2 cipher list。

必须保持的协议不变量：

| 场景 | ClientHello ALPN | 握手后首个应用协议 |
| --- | --- | --- |
| 裸 Trojan/TLS | 不发送 ALPN | Trojan 请求 |
| Trojan over WSS | 只发送 `http/1.1` | HTTP/1.1 WebSocket Upgrade |
| VLESS 客户端 | 当前未实现 | 不建立客户端基线 |

服务端只选择客户端提供的 `http/1.1`。如果没有共同 ALPN，则不协商 ALPN。服务端还必须在握手阶段拒绝缺失或错误 SNI。

这些约束优先于“看起来像浏览器”。例如，给 WSS 客户端增加 `h2` 虽然可能让 ClientHello 更接近普通浏览器，但 CDN 或服务端一旦选择 `h2`，当前客户端并没有 HTTP/2 或 RFC 8441 状态机，结果会变成明确的跨层协议错误。

## 3. 四层观测模型

单一 JA4 值不足以覆盖回归，应同时保存四层结果。

### 3.1 TLS 原始结构

从 ClientHello 和服务端握手消息提取：

- legacy version 与 `supported_versions`；
- cipher suites 原始顺序；
- extension 类型原始顺序；
- SNI 是否存在，测试环境中可校验固定测试域名；
- ALPN 列表及顺序；
- signature algorithms、supported groups 和 key share group 顺序；
- GREASE 是否存在、数量和位置；
- session ID、PSK、ticket、early data、ECH、OCSP、SCT、certificate compression 等扩展是否存在；
- ClientHello 总长度、TLS record 数量和 record 长度；
- ServerHello 选择的版本、cipher、ALPN、扩展和是否发生 HelloRetryRequest；
- 成功、alert 类型、超时或 TCP 关闭。

随机值不能直接进入稳定基线。Client random、session ID 内容、key share 公钥和 ticket 内容应删除；GREASE 值应归一化为占位符，但保留其位置。

### 3.2 派生指纹

至少输出：

- JA4；
- JA4 raw，即排序后的原始组成字段；
- JA4 original-order 变体，用于发现 cipher 或 extension 顺序变化；
- JA4S，且必须绑定到产生它的固定 ClientHello 测试向量；
- 可选 JA3/JA3S，仅用于与旧工具对照，不作为唯一门禁。

JA4 会忽略 GREASE，并对 cipher 和 extension 列表排序，因此相同 JA4 不代表线上的 ClientHello 完全相同。原始顺序和扩展语义仍需单独比较。

### 3.3 应用层一致性

抓包或端到端测试还必须确认：

- 裸 TLS 未声明 HTTP，握手后也没有发送 HTTP；
- WSS 协商 `http/1.1` 后，首个请求确实是合法 HTTP/1.1 Upgrade；
- WebSocket path、Host、Upgrade、Connection、Version 和 Key 符合预期；
- 服务端返回 `101` 后才发送二进制隧道数据；
- fallback 的 `200/400/404/405`、CRLF、Content-Length 和关闭行为稳定；
- 错误 SNI、缺失 SNI、错误密码和非 HTTP 探测得到预期失败方式。

解密应用数据不是计算 JA4 的前提。需要检查加密后的 HTTP 内容时，可以在仅用于测试的构建中使用 BoringSSL key-log callback，输出 NSS `SSLKEYLOGFILE` 格式，再交给 Wireshark。密钥日志能够解密会话，必须作为敏感临时文件处理，禁止提交仓库或上传公共 CI artifact。

### 3.4 TCP 与环境特征

TCP option、初始窗口、MSS、分段、重传和时序主要由操作系统、网络路径和运行负载决定。它们可以作为独立的环境报告或 JA4T 类指标，但不应阻塞 TLS 库的普通 pull request。

## 4. 测试矩阵

### 4.1 最小 PR 门禁

每个测试至少重复 5 次，以识别 GREASE、扩展排列或会话状态带来的多值结果。

| 用例 | 传输 | TLS | 配置 | 关键断言 |
| --- | --- | --- | --- | --- |
| C1 | 裸 Trojan | 默认优先 TLS 1.3 | 默认 cipher | 无 ALPN，Trojan 数据可转发 |
| C2 | WSS | 默认优先 TLS 1.3 | 默认 cipher | ALPN 仅 `http/1.1`，Upgrade 成功 |
| C3 | 裸 Trojan | TLS 1.2 对端 | 默认 cipher | 版本和 cipher 在允许集合内 |
| C4 | 裸 Trojan | TLS 1.2 对端 | 自定义 cipher | ClientHello 与协商结果反映配置 |
| S1 | 服务端 | TLS 1.3 | 正确 SNI、无 ALPN | 握手成功且不协商 ALPN |
| S2 | 服务端 | TLS 1.3 | 正确 SNI、`http/1.1` | 选择 `http/1.1` |
| S3 | 服务端 | TLS 1.3 | 错误或缺失 SNI | `unrecognized_name` 致命告警 |
| S4 | 服务端 | TLS 1.2 | 固定测试 ClientHello | JA4S 与选择结果匹配基线 |

TLS 1.2 用例应使用能够固定最大版本的测试对端。当前业务配置只设置最低版本，不应为了测试而增加生产配置项；可以在集成测试 helper 中构造受限 `SslAcceptor`，或使用固定版本的 `openssl s_server -tls1_2`。

### 4.2 发布前扩展矩阵

发布前增加：

- Linux glibc x86_64 与 aarch64；
- Linux musl x86_64 与 aarch64；
- Windows x86_64 MSVC；
- macOS x86_64 与 arm64；
- IPv4 与 IPv6 loopback；
- 首次连接、连续新连接和明确实现后的会话恢复；
- RSA 与 ECDSA 服务端证书；
- 正确、错误、缺失、大小写变化的 SNI；
- WebSocket 正确 path、错误 path、超大 header、慢速 header 和非 binary frame；
- BoringSSL、`boring`、`tokio-boring` 或 Rust 工具链升级前后的 A/B 抓包。

跨平台 TLS 结构理想情况下相同，但不能先假定相同。首次建立基线时应分别采集；确认多个目标长期一致后，才可合并为共享基线。

## 5. 可复现实验拓扑

推荐在 Linux CI 的 loopback 上完成强制门禁，避免公网路径、DNS 和第三方服务变化：

```text
curl -> SOCKS5 127.0.0.1:11080
     -> trojan-rs client
     -> TLS/WSS 127.0.0.1:18443, SNI fp.test
     -> trojan-rs server
     -> local HTTP echo 127.0.0.1:18080
```

测试证书由临时 CA 签发，SAN 包含 `fp.test`。客户端 `tls.addr` 指向 `127.0.0.1:18443`，`tls.sni` 保持 `fp.test`，并通过 `tls.cert` 信任临时 CA。证书和私钥只用于测试。

一个典型抓包流程如下，具体脚本应负责进程就绪检查、超时和清理：

```shell
mkdir -p target/fingerprint
sudo dumpcap -i lo -f 'tcp port 18443' \
  -a duration:20 -w target/fingerprint/c1.pcapng &
capture_pid=$!

# 启动本地 echo、server 和 client 后触发 SOCKS 请求。
curl --fail --socks5-hostname 127.0.0.1:11080 \
  http://127.0.0.1:18080/health
wait "$capture_pid"
```

不要依赖固定 `sleep` 判断服务已经启动。测试 driver 应轮询本地监听端口和健康状态，并为每个子进程设置总超时。

捕获与解析工具应固定版本。建议使用固定 digest 的 Wireshark/tshark 容器，或在 CI 中记录以下元数据：

- Wireshark、tshark、dumpcap 和 JA4 插件版本；
- `rustc -Vv`；
- target triple；
- `Cargo.lock` SHA-256；
- `boring`、`boring-sys` 和 `tokio-boring` 版本；
- git commit；
- 测试配置摘要和证书类型。

## 6. Artifact 与基线格式

建议目录：

```text
tests/fingerprint/
  fixtures/
  baselines/
    linux-x86_64-gnu/
      raw-tls13.json
      wss-tls13.json
      raw-tls12.json
  scripts/
target/fingerprint/
  *.pcapng
  *.normalized.json
  *.diff.json
  metadata.json
```

仓库只提交归一化 JSON 和生成脚本，不提交包含真实地址、SNI、票据或密钥材料的生产抓包。合成测试 pcap 可以作为短期 CI artifact，但应设置较短保留期。

归一化记录至少包含：

```json
{
  "schema": 1,
  "case": "wss-tls13",
  "transport": "tcp",
  "client_hello": {
    "supported_versions": ["GREASE", "0304", "0303"],
    "ciphers_original": ["GREASE", "1301", "1302"],
    "extensions_original": ["GREASE", "0000", "0010"],
    "alpn": ["http/1.1"],
    "signature_algorithms": [],
    "supported_groups": [],
    "key_share_groups": [],
    "length": 0
  },
  "negotiated": {
    "version": "TLSv1.3",
    "cipher": "",
    "alpn": "http/1.1"
  },
  "fingerprints": {
    "ja4": "",
    "ja4_raw": "",
    "ja4_original_order": "",
    "ja4s": ""
  }
}
```

示例中的空值和长度 `0` 只是 schema 占位，不是本项目当前指纹基线。基线必须由固定工具对实际构建抓包生成，不能手工猜测。

## 7. 比较规则与门禁级别

### 7.1 必须失败

- 最低版本降到 TLS 1.2 以下；
- 证书或主机名验证被关闭；
- 错误/缺失 SNI 被服务端接受；
- 裸 Trojan 意外出现 ALPN；
- WSS 不再发送或协商 `http/1.1`；
- 声明 `h2`、`h3` 等未实现协议；
- cipher、signature algorithm 或 group 出现明确不安全回退；
- 握手成功但首个应用层消息不符合协商的 ALPN；
- 测试从成功变成 alert、超时或异常关闭。

### 7.2 需要显式批准基线更新

- cipher、extension、signature algorithm 或 supported group 的集合/顺序变化；
- GREASE、extension permutation、OCSP、SCT、ECH、certificate compression 或 PSK 行为变化；
- JA4、JA4 raw、original-order 指纹或 JA4S 变化；
- ClientHello/ServerHello record 结构和长度发生稳定变化；
- BoringSSL 或 Rust wrapper 升级导致可解释的握手差异。

基线更新必须在 pull request 中同时提交：归一化前后差异、依赖变化原因、安全与兼容性判断，以及至少一次人工 Wireshark 检查结果。禁止 CI 自动覆盖基线。

### 7.3 只告警

- IP packet 分段、TCP timestamp、窗口、MSS 和重传变化；
- loopback 调度造成的握手时延变化；
- ClientHello 长度的小范围多值分布，但结构字段不变；
- 不同操作系统网络栈产生的 JA4T 类变化。

## 8. CI 分层

### 8.1 每次提交

- 现有 Rust 单元测试；
- TLS 配置和 ALPN 不变量测试；
- 不需要抓包权限的内存或 loopback 握手测试；
- 归一化 parser 的固定 fixture 测试。

### 8.2 Pull request 的 Linux 抓包 job

- 安装固定版本的 dumpcap/tshark；
- 构建 client/server；
- 生成临时 CA 与证书；
- 执行最小矩阵并采集 loopback pcap；
- 从 pcap 生成 normalized JSON；
- 与 `tests/fingerprint/baselines/linux-x86_64-gnu` 比较；
- 上传 pcap、metadata 和 diff，失败时保留供人工分析。

### 8.3 Nightly 或发布前

- 全平台矩阵；
- Chrome/Firefox 控制组参考采集；
- 旧发行版与当前 HEAD 的 A/B 对比；
- 重复 20 至 50 次，检查是否存在多个合法指纹族；
- 公网或 CDN 路径只作为观察性报告，不替代 loopback 门禁。

## 9. 伪装页能否采集真实 TLS 指纹

### 9.1 可以采集，但不是由页面采集

TLS ClientHello 在任何 HTTP 请求和页面 JavaScript 执行之前发送。JavaScript、HTML 和 fallback handler 无法读取本连接的 ClientHello。可行的采集点是：

1. TLS 终止进程的 ClientHello callback；
2. TLS 终止主机上的受控抓包；
3. 掌握该能力的负载均衡器或 CDN 边缘日志。

当前使用的 Rust `boring 5.1.0` 暴露了 `set_select_certificate_callback`。其 `ClientHello` 对象能够读取原始 ClientHello、cipher 列表、SNI 和指定扩展，因此技术上可以在当前 TLS acceptor 中加入诊断采集。但 callback 位于握手关键路径，不能进行同步文件、网络或数据库 I/O。

推荐实现方式是：callback 只在内存中完成大小受限的归一化，把记录 `try_send` 到有界 channel；后台 task 再做采样、聚合和输出。队列满时丢弃采样，不能阻塞握手。

### 9.2 CDN 是硬边界

如果 TLS 在 CDN 边缘终止，trojan-rs 源站观察到的是 CDN 到源站的 ClientHello，不是浏览器到 CDN 的 ClientHello。伪装页部署在 CDN 后面时，源站无法从普通 HTTP header 还原真实 ClientHello。只有 CDN 明确提供并可信传递相应指纹字段时，才能使用边缘计算结果。

因此，浏览器参考采集应使用一个专门的直连测试域名，由受控采集器直接终止 TLS。不要把生产代理入口暴露为公共指纹收集服务。

### 9.3 页面能够提供的辅助信息

fallback 可以把同一 TLS 连接上的 ClientHello 记录与以下 HTTP 信息关联：

- User-Agent；
- `Sec-CH-UA` 等低熵 Client Hints；
- 请求路径和服务端生成的一次性实验 ID；
- 由受控自动化环境预先登记的浏览器、版本和操作系统标签。

User-Agent 和 Client Hints 都可能缺失、被修改或受隐私策略限制，不能作为真实浏览器版本的绝对证据。高熵 Client Hints 通常还涉及 `Accept-CH` 和后续请求。页面触发的新资源请求也可能复用原 TLS 连接，因此不能假定每个资源对应一个新 ClientHello。

最可靠的参考数据来自受控浏览器矩阵：干净 profile、明确浏览器版本、操作系统、启动参数和网络协议设置，并由测试 driver 主动访问采集域名。

## 10. 能否据此反向调整 BoringSSL

可以做有限、受约束的调整，但不能从若干真实浏览器抓包自动推导出“Chrome TLS 实现”。

当前 `boring 5.1.0` 可控制的典型项目包括：

- TLS 1.2 cipher list；
- ALPN；
- signature algorithms；
- supported curves/groups；
- GREASE；
- ClientHello extension permutation；
- OCSP stapling 和 SCT 请求；
- 部分 ECH/ECH GREASE 行为。

当前 trojan-rs 只使用了其中的版本、TLS 1.2 cipher 和 ALPN 等基础配置。即使补齐这些开关，也不能自动获得浏览器一致性。浏览器指纹还受到 BoringSSL 精确 revision、Chromium 网络栈、HTTP/2/HTTP/3、ALPS/application settings、certificate compression、delegated credentials、会话恢复、ECH、实验开关、扩展排列、record 行为和操作系统 TCP 栈影响。

建议把差异分为三类：

| 类型 | 示例 | 处理原则 |
| --- | --- | --- |
| 安全且与传输一致的 TLS 参数 | GREASE、group、sigalg | 在兼容性测试后可评估调整 |
| 需要完整上层实现 | `h2`、`h3`、ALPS、QUIC | 先实现协议，再修改 ClientHello |
| 环境或浏览器私有行为 | TCP、实验 cohort、版本快速变化 | 不在 TLS 库中硬编码追随 |

不建议恢复旧式 `fingerprint = "chrome"` 配置或从访问者样本自动生成线上模板。固定模板会快速过期，并可能产生“TLS 声明像浏览器，但后续流量不像浏览器”的更强异常。

更合理的优化目标是：

1. 消除明显的 TLS/ALPN/HTTP 矛盾；
2. 跟踪 BoringSSL 升级带来的非预期变化；
3. 保持安全参数和主流服务端兼容性；
4. 如果未来确实需要浏览器型 WSS，先完成相应 HTTP/2、会话和扩展语义，再维护按版本验证的独立实现，而不是只修改 cipher 和扩展顺序。

## 11. 采集安全与隐私边界

原始 ClientHello 可能包含 SNI、PSK identity、session ticket 和可用于关联连接的值。生产采集至少应满足：

- 默认关闭，只允许显式诊断配置或独立测试构建启用；
- 只保存归一化字段，SNI/IP 使用删除、分桶或带轮换密钥的 HMAC；
- 不保存 random、key share、公钥字节、ticket、PSK identity 或密钥日志；
- 固定采样率、短保留期、容量上限和访问审计；
- callback 使用有界队列，采集故障不能影响握手；
- 对公开用户采集前评估适用的告知、同意和数据保护要求；
- 只对自有系统和获得授权的测试流量进行抓包。

## 12. 推荐实施顺序

1. 先实现归一化 schema、fixture parser 测试和 C1/C2 loopback 抓包。
2. 加入 S1 至 S4 固定 ClientHello 向量，建立 JA4S 基线。
3. 在 Ubuntu CI 增加非自动更新的基线门禁。
4. 增加 TLS 1.2、证书类型和跨平台 nightly 矩阵。
5. 如需应用层解密，仅增加 test-only keylog feature。
6. 最后搭建独立、直连、受控浏览器参考采集器；先做报告，不直接驱动线上参数。

## 13. 验收标准

测试系统完成后应满足：

- 单条命令可以生成 C1/C2 的 pcap、normalized JSON 和 diff；
- 相同 commit 连续运行不会因随机字段产生假失败；
- 修改裸 TLS/WSS ALPN 时测试必定失败；
- 修改 cipher、group、sigalg 或扩展行为时生成可读结构化差异；
- BoringSSL 依赖升级必须显式审核基线；
- 生产二进制默认不包含启用的抓包、原始 ClientHello 日志或 keylog 输出；
- 浏览器参考数据与代理客户端基线分开保存，不把两者误认为同一种协议画像。

## 参考资料

- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/info/rfc8446/)
- [RFC 7301: TLS Application-Layer Protocol Negotiation](https://www.rfc-editor.org/info/rfc7301/)
- [RFC 9325: Recommendations for Secure Use of TLS and DTLS](https://www.rfc-editor.org/info/rfc9325/)
- [RFC 9849: TLS Encrypted Client Hello](https://www.rfc-editor.org/info/rfc9849/)
- [BoringSSL SSL API](https://boringssl.googlesource.com/boringssl/+/main/include/openssl/ssl.h)
- [boring crate SSL API](https://docs.rs/boring/5.1.0/boring/ssl/)
- [JA4 TLS Client Fingerprinting](https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
- [JA4+ Wireshark Plugin](https://github.com/FoxIO-LLC/ja4/blob/main/wireshark/README.md)
- [Wireshark TLS Documentation](https://wiki.wireshark.org/TLS)
