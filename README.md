# Trojan-rs

专为 **NAT VPS** 与嵌入式低端设备深度优化的轻量级、高性能代理服务端，基于 Rust 实现。R 意为 **R**ust / **R**apid。

**Trojan-rs 目前为实验性项目，仍处于重度开发中，协议、接口和配置文件格式均可能改变，请勿用于任何生产环境。**

## 特性

- 专为 NAT VPS 优化

    保持单文件部署与较小的运行时内存占用，彻底去除正则引擎等无关依赖，禁用所有非核心功能。在内存只有 128MB 甚至 64MB 的低端 NAT 主机上也能运行。

- 丰富的协议解析与承载

    原生支持多种主流代理协议与传输层组合的解析和转发：
    - **核心协议**: 支持 `Trojan`、`VLESS`、`Socks5` 协议栈。
    - **传输层**: 支持基础的 `Direct` (TCP/UDP 直连) 和抗阻断的 `WebSocket` (WS/WSS)。
    - **安全层**: 支持基于静态链接 `BoringSSL` 的 `TLS` 加密承载，以及主动探测防御的协议回落 (Fallback)。

- 极致性能

    牺牲部分灵活性，采用激进的性能优化策略以极力减少不必要的开销。TLS 由 BoringSSL 提供，并直接集成到异步 Tokio I/O 路径中。
    使用 tokio 异步运行时，允许 `Trojan-rs` 同时使用所有 CPU 核心，保证低时延和高效的吞吐能力。

- 低内存占用

    Rust 无 GC 机制，内存占用可被预计。简化的握手和连接流程，仅使用极少的堆内存和复制。

- 简易配置

    使用 toml 格式配置，仅需数行配置即可启动完整客户端或服务器。

- 内存安全

    使用 Rust 语言实现，可证明的内存安全性。在语法层面保证所有内存操作安全可靠。无竞争条件，无悬挂指针，无 UAF，无 Double Free。

- 密码学安全

    使用 `BoringSSL` 建立 TLS 加密安全信道，最低协议版本为 TLS 1.2。`Trojan-rs` 强制开启服务器证书与主机名校验以防止中间人攻击。

- 隐蔽传输

    `Trojan-rs` 使用 TLS 建立代理隧道，并支持协议回落。客户端与服务端统一使用 BoringSSL 的原生握手行为，不再提供过期的浏览器 ClientHello 模板。裸 Trojan 不声明 ALPN，WSS 使用 `http/1.1`；服务端会校验配置的 SNI、证书域名和 TLS 握手超时。内置 fallback 仅响应规范 HTTP 请求，并提供根页面、`/index.html` 和 `/robots.txt` 路由。

- 跨平台支持

    `Trojan-rs` 可被交叉编译，支持 Android， Linux，Windows 和 MacOS 等操作系统，以及 x86，x86_64，armv7，aarch64 等硬件平台。

## 非特性

由于与项目的设计原则冲突，下列特性不计划实现

- 统计功能，包括 API 和数据库对接等
- 路由功能
- 用户自定义协议栈
- 透明代理

如果需要实现上述功能，请使用其他类似工具与 `Trojan-rs` 组合实现。

## 设计原则

- 安全性

    `Trojan-rs` 不涉及底层操作，且目前的性能瓶颈与其无关，无使用 unsafe rust 的必要。协议回落和 TLS 配置等安全敏感代码经过仔细考虑和审计，同时也欢迎更多来自开源社区的安全审计。
    目前 `Trojan-rs` 使用 `#![forbid(unsafe_code)]` 禁用 unsafe rust。如未来有必要使用 unsafe rust 时，必须经过严格审计和测试。

- 使用静态分发而非动态分发

    协议实现使用统一的 trait。协议嵌套使用静态分发，以保证嵌套协议栈的函数调用关系在编译时被确定，使编译器可以进行内联和更好的优化。

- 低内存分配

    减少热点代码的内存分配，用引用替换复制，以实现更高的性能和更低的内存开销。

- 简洁

    保持最简洁干净的实现，以保证最低的代码复杂度，尽可能少的性能开销，并增加可靠性和减少攻击面。

## 部署和使用

### 推荐架构与配置方式

对于绝大多数 NAT VPS 用户，我们强烈推荐使用以下组合以最大化连通性、隐蔽性和性能：
**VLESS / Trojan + WebSocket (WSS) + TLS + CDN**

- **架构解析**：将您的域名接入 CDN（如 Cloudflare，并点亮小黄云）。服务端暴露常规的 443 或任意自定义端口，客户端的流量先经过 CDN 边缘节点，再通过 WebSocket 发送到您的源站。
- **防探测机制**：自带高度定制的 Web Fallback（协议回落）功能。遇到非正常的 GFW 主动探测或未知爬虫访问时，自动返回一个以假乱真的静态“IP 查询站点”伪装页面，彻底隐藏代理服务特征。

### 服务端一键部署 (推荐)

我们为 Linux 服务端提供了交互式一键部署与管理脚本。支持一键安装上述推荐的 **Trojan+WSS** 或 **VLESS+WSS** 架构、生成并下发 Clash 客户端配置、配置 systemd 服务。内置 acme.sh 脚本，通过纯手动 DNS-01 模式为您签发完全合法的 TLS 证书（即使 80 端口被封死的小鸡也能签发）。

在支持的系统环境 (Ubuntu / Debian / CentOS) 上，您只需执行以下命令即可：

```shell
wget https://raw.githubusercontent.com/tuxco-de/trojan-rs/main/scripts/install.sh
chmod +x install.sh
sudo ./install.sh
```

### 手动部署与客户端使用

`Trojan-rs` 核心程序原生使用 TOML 格式进行配置。如需手动部署服务端或运行客户端程序，请参考项目仓库 `config` 文件夹下的配置文件模板示例。

## 编译

```shell
cargo build --release
```

BoringSSL 源码由 `boring-sys` 在构建时编译，并以静态库链接到最终程序。构建机需要 CMake、Clang、libclang，以及目标平台可用的 C/C++ 工具链；x86/x86_64 构建还需要 NASM。

Ubuntu/Debian 构建依赖示例：

```shell
sudo apt-get install -y build-essential cmake clang libclang-dev ninja-build
```

交叉编译基于 `cross` 完成，编译镜像同样必须包含上述 BoringSSL 构建工具链。默认发布目标使用 glibc；BoringSSL 本身仍为静态链接。

```shell
make aarch64-unknown-linux-gnu
```

编译默认开启链接时优化，以提升性能并减小可执行文件体积，因此编译耗时可能较其他项目更长。
编译完成后可以使用 `strip` 去除调试符号表以减少文件体积。

## TODOs

- [x] 更完善的交互接口和文档
- [ ] 更多的单元测试和集成测试
- [ ] 性能调优
- [ ] 可复现的 benchmark 环境
- [ ] 实现 lib.rs 和导出函数
- [x] 分离客户端和服务端 features
- [x] Github Actions 跨平台持续集成与全自动构建发布

## 致谢

- [trojan](https://github.com/trojan-gfw/trojan)
- [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
