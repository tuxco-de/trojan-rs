# 深入解析 HTTP/1.1 与 HTTP/2 协议伪装及回退 (Fallback) 机制

在网络代理与对抗网络审查（如深度包检测 DPI）的场景中，**流量伪装（Traffic Camouflage）**与防**主动探测（Active Probing）**是保证服务器安全生存的关键。`trojan-rs` 通过内置一个轻量级的、双协议（HTTP/1.1 & HTTP/2）静态 Web 服务器（Fallback），完美伪装成一个正常的 HTTPS 网站。

本文将深入分析 ALPN 协议协商机制，剖析 `trojan-rs` 中对 HTTP/1.1 和 HTTP/2 回退机制的具体实现，并分享防主动探测的行业最佳实践。

---

## 一、 防探测的核心：回退 (Fallback) 机制与 ALPN

### 1. 什么是主动探测？
防火墙或审查者如果怀疑某个 IP 是代理服务器，会主动向该 IP 的对应端口（如 443）发送常规的 HTTP 请求，或者发送随机的垃圾数据：
* 如果服务器**直接断开连接**，或者**没有任何响应**，就会暴露其“非正常 Web 服务器”的特征，从而被封锁。
* 如果服务器能像标准的 Nginx 或 Apache 一样，返回一个精美的 HTML 静态网页（或者返回标准的 400 Bad Request），审查者就会认为这只是一个普通的个人网站。

### 2. ALPN (Application-Layer Protocol Negotiation)
在建立 TLS 安全隧道时，客户端和服务器必须在握手阶段决定后续应用层使用什么协议。这就是 **ALPN**。
* `trojan-rs` 的 TLS 层同时向外宣告支持 `h2`（HTTP/2）和 `http/1.1`。
* 根据客户端（或探测者）在 TLS ClientHello 中携带的 ALPN 列表，服务端进行协商分流。

#### ALPN 协商与 Fallback 分流流程图

```mermaid
flowchart TD
    C["客户端/探测者"] ===|1. TLS 握手 (ClientHello + ALPN: h2, http/1.1)| T["Trojan-rs 监听器 (443)"]
    
    T -->|2. TLS 握手完成| ALPN{协商出的协议是什么?}
    
    ALPN -->|ALPN: h2| H2["HTTP/2 路径 (serve_h2)"]
    ALPN -->|ALPN: http/1.1| H1["HTTP/1.1 路径 (serve)"]
    ALPN -->|无 ALPN| H1

    H2 --> H2_Handshake["h2::server::handshake"]
    H2_Handshake --> H2_Router{"是否为合法的 VLESS/WSS 握手?"}
    H2_Router -->|是| Proxy_H2["执行代理业务"]
    H2_Router -->|否| Web_H2["返回 HTTP/2 静态网页/Dashboard"]

    H1 --> H1_Header{"首包是否为合法 Trojan 握手?"}
    H1_Header -->|是| Proxy_H1["执行 Trojan 代理"]
    H1_Header -->|否| H1_Validate{"是否为 HTTP 请求?"}
    H1_Validate -->|是| Web_H1["返回 HTTP/1.1 静态网页/Dashboard (Connection: close)"]
    H1_Validate -->|否 (垃圾数据)| Close_H1["静默关闭连接 (仿 Nginx 行为)"]
```

---

## 二、 `trojan-rs` 中的 HTTP/1.1 回退实现

在 [src/protocol/fallback.rs](file:///d:/dev/trojan-rs/src/protocol/fallback.rs) 中，`FallbackPage::serve` 方法负责处理 HTTP/1.1 请求。

### 1. 限制请求头大小以防 DoS 攻击
由于 HTTP/1.1 请求是纯文本格式，解析器必须读取到 `\r\n\r\n`（请求头的结束标志）才能开始解析。为了防止恶意客户端发送无限长的垃圾数据撑爆内存，`trojan-rs` 限制了最大读取长度（`max_request_size`，默认 8 KiB）：

```rust
let request = if find_header_end(&prefix).is_some() {
    prefix
} else {
    let mut request = prefix;
    while find_header_end(&request).is_none() {
        if request.len() >= max_request_size {
            break;
        }
        // ... 异步读取并追加到 request 缓冲区
    }
    request
};
```

### 2. 路由匹配与安全认证
系统通过 `route_request` 函数对请求的 Path 和 Header 进行分析：
* **普通路由**：`GET /` 或 `GET /index.html` 返回用户配置的伪装 HTML 页面。`GET /robots.txt` 返回防爬虫规则。
* **Dashboard 路由**：内置了一个管理面板（`GET /dashboard`）和 API 监控（`GET /api/status`）。
* **Basic 认证**：管理面板需要经过 HTTP 基础认证。服务端会检查请求头中的 `Authorization: Basic <base64(admin:password)>`。如果未配置密码或校验失败，返回 `401 Unauthorized`，并携带 `WWW-Authenticate` 头部促使浏览器弹出密码输入框。

### 3. 连接关闭策略
由于这是一个极其轻量级的伪装服务器，它**不支持 HTTP/1.1 Keep-Alive（长连接）**。在发送响应后，服务端会在响应头中加入 `Connection: close`，并立即关闭套接字。这不仅简化了代码设计，也避免了探测者占用服务器的连接通道。

---

## 三、 `trojan-rs` 中的 HTTP/2 回退实现

当 ALPN 协商为 `h2` 时，`FallbackPage::serve_h2` 会被调用。HTTP/2 是一个二进制分帧协议，不支持直接按文本解析，必须进行完整的状态机握手。

### 1. 基于 `h2` 库的握手机制
`trojan-rs` 使用了 Rust 生态中高性能的 `h2` 库来进行 HTTP/2 握手与流管理：

```rust
pub fn serve_h2<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(&self, stream: T) {
    let page = self.clone();
    tokio::spawn(async move {
        // 1. 进行 HTTP/2 Connection 握手
        let mut connection = match timeout(page.request_timeout, h2::server::handshake(stream)).await {
            Ok(Ok(connection)) => connection,
            // ... 异常处理
        };
        // 2. 循环接收并在同一个 TCP 连接上并发处理多个 H2 Stream
        while let Some(request) = connection.accept().await {
            let (request, respond) = request?;
            let route = route_h2_request(&request, page.dashboard_password.as_deref());
            page.write_h2_response(route, respond).await?;
        }
    });
}
```

### 2. 多路复用响应 (Multiplexed Responses)
与 HTTP/1.1 不同，HTTP/2 允许在同一个连接上并行发送多个请求和响应。`connection.accept().await` 会产生一个个独立的 `Stream`。
`write_h2_response` 将 `http::Response` 转换成 H2 帧发回：
* 先发送 **HEADERS 帧** 传递状态码（如 `200 OK`）和 `content-type`。
* 再发送 **DATA 帧** 写入网页的 HTML 字节流。

---

## 四、 行业最佳实践：前置 Web 服务器分流 (反向代理)

虽然 `trojan-rs` 内置的 Fallback 服务端非常方便，但在极其严苛的生产环境中，业界更推荐使用 **前置主流 Web 服务器（如 Nginx、Caddy、HAProxy）** 进行 TLS 终结和分流。

#### Nginx + Trojan 前置分流拓扑

```mermaid
flowchart LR
    C["客户端/探测者"] -->|443 端口 (TLS)| N["Nginx (前置 Web 服务)"]
    
    subgraph InsideServer ["服务器内部"]
        N -->|1. 正常的 HTTPS 流量 / 探测流量| L["本地静态网页 / PHP / API"]
        N -->|2. 符合特定的 SNI 或 Path / 代理协议流量| T["Trojan-rs (监听本地 127.0.0.1:10086)"]
    end

    T -->|转发| Web["目标网站"]
    
    style InsideServer fill:#f5f5f5,stroke:#ccc
```

### 为什么前置 Nginx/Caddy 更安全？
1. **无可挑剔的指纹**：内置的轻量级 Fallback 服务器在遇到复杂的 HTTP 特性（如 gzip 压缩、Range 请求、HTTP/2 头部优化 HPACK、Keep-Alive 行为）时，表现可能与标准 Nginx 存在微小差异。老练的防火墙可以通过这些微小的**行为指纹（Behavioral Fingerprinting）**判定其非真实 Web 服务。而前置 Nginx 则是 100% 真实且成熟的 Web 服务。
2. **多站点共用端口**：你可以将代理服务隐藏在一个真实运行着企业官网、个人博客的 Nginx 后面。通过判断请求的 `Path`（如 `/my-secret-entry`）或者特定的 `SNI`，Nginx 将代理流量转发给本地的 `trojan-rs`，其余流量正常访问博客，伪装天衣无缝。

---
*本文档收录于项目的知识库建设，旨在帮助开发者掌握高强度流量混淆与 Web 伪装技术的实现细节。*
