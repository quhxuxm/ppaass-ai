# 测试指南

本文档说明当前仓库的测试分层、CI 覆盖范围、在本地运行的命令，以及端到端和性能测试的
前置条件。以工作流、测试 crate 与 [`run-tests.sh`](../run-tests.sh) 的实际行为为准。

## 1. 测试分层概览

| 层级 | 主要位置 | 验证目标 | 常用入口 |
| --- | --- | --- | --- |
| 结构与发布契约 | `scripts/` | 源码行数、Rust 测试布局、Entry/Registry 部署文件边界 | `check-source-line-limits.sh`、`test-proxy-deployment-layout.sh` |
| Rust 集成测试 | 各 crate 顶层 `tests/` | 协议、加密、状态存储、控制面、转发、TUN 与平台适配 | `cargo test --workspace --locked` |
| Web/桌面前端测试 | `proxy-registry/frontend`、`desktop-agent-ui` | 页面结构、认证流程、配置序列化、凭据处理 | `npm test` |
| Android 测试 | `android-agent`、`android-agent/native` | Java/Kotlin 单元测试、Android lint、JNI/Rust native 行为 | Gradle、`cargo test --manifest-path` |
| 端到端集成测试 | `tests/` crate | Mock Target → Entry → 测试专用 Agent → HTTP/SOCKS5 客户端 | `run-tests.sh integration` |
| 性能/诊断测试 | `tests/` crate | TCP、UDP、QUIC、Range 下载、端到端峰值吞吐 | `run-tests.sh <mode>` |

Rust 的产品 crate 将测试放在所属 crate 顶层 `tests/`，通过公开 API 进行 Cargo
integration test。仓库检查会拒绝在 `src/` 中放置 `#[test]`、`#[cfg(test)]` 或测试模块，
也会拒绝通过 `include!`、`#[path]` 或 `../src` 绕过公开 API。

`tests/` 是一个独立的集成/性能测试工具 crate：其可执行程序负责启动 mock 服务、驱动真实
服务进程并生成报告；它本身的 Cargo 集成测试位于 `tests/tests/`。

## 2. 合并前的最小验证集

在仓库根目录运行下列命令。`--locked` 可确保使用 `Cargo.lock` 中锁定的依赖版本。

```bash
# 结构规则：其中也会调用 Rust 测试布局检查
./scripts/check-source-line-limits.sh
bash ./scripts/test-proxy-deployment-layout.sh

# Rust workspace：构建所有 target 并执行所有 crate 的集成测试
cargo build --workspace --all-targets --release --locked
cargo test --workspace --locked
```

若改动 Registry 前端，继续执行：

```bash
cd proxy-registry/frontend
npm ci --no-audit --no-fund
npm test
npm run build
```

若改动桌面前端或其凭据/配置逻辑，执行：

```bash
cd desktop-agent-ui
npm ci
npm test
cargo test --manifest-path src-tauri/Cargo.toml --locked
```

桌面应用的完整打包（Windows 或 macOS）还需要相应平台上的 Tauri 依赖：

```bash
cd desktop-agent-ui
npm run tauri build
```

若改动 Android Java/Kotlin 或 native Rust，按第 6 节的 Android 命令运行。部署脚本、发布
布局或端口配置变更至少应运行两个 `scripts/` 检查；部署工作流本身不替代这些合并前验证。

## 3. GitHub Actions 覆盖范围

### 3.1 单元测试工作流

[`unit-test.yml`](../.github/workflows/unit-test.yml) 在手动触发、推送到 `main` 或
`develop-*` 分支、以及所有 pull request 时执行，包含四个任务：

| 任务 | 环境与工具链 | 实际检查 |
| --- | --- | --- |
| Rust workspace | Debian Bookworm、Rust 1.98.1 | 结构/部署布局检查、`cargo build --workspace --all-targets --release --locked`、`cargo test --workspace --locked` |
| Registry frontend | Debian Bookworm、Node 24 | `npm ci`、`npm test`、`npm run build` |
| Desktop build | Windows 与 macOS、Node 22、Rust 1.95.0 | 桌面前端测试、Tauri Rust 测试、Tauri 打包；Windows 安装包保留为 14 天 artifact |
| Android agent | Debian Bookworm、JDK 17、Android API 35、NDK 28.2.13676358、Rust 1.95.0 | Gradle 单元测试/lint、native Rust 测试、三种 ABI 的 native build、debug APK artifact |

### 3.2 端到端集成工作流

[`integration-test.yml`](../.github/workflows/integration-test.yml) 在推送到 `main` 和
pull request 时执行。它在同一 Debian Bookworm 容器中依次启动：

```text
Mock Target (HTTP :9090 / H2 :9093 / TCP :9091 / UDP :9092)
        │
Proxy Entry (:8080，测试 fixtures 配置)
        │
Desktop Agent integration harness (:7080)
        │
integration-tests 客户端
```

工作流使用 Rust 1.98.1 与 Node 20；Node 仅用于 `npx wait-on` 等待服务端口就绪。最后它会
运行 `integration-tests integration`，覆盖通过 Agent 的 HTTP、CONNECT、SOCKS5 TCP 与
SOCKS5 UDP 通路，以及大响应、Range 分片、HTTP/2 多路复用、取消、慢读、背压、目标失败
和会话恢复等回归场景。

### 3.3 静态分析和安全扫描

这些工作流提供额外信号，但不要把它们误认为替代测试：

| 工作流 | 触发时机 | 说明 |
| --- | --- | --- |
| [`rust-clippy.yml`](../.github/workflows/rust-clippy.yml) | `main` push/PR、每周定时 | 生成并上传 Clippy SARIF；当前分析步骤配置为 `continue-on-error`，因此是告警而非阻断门禁 |
| [`checkmarx-one.yml`](../.github/workflows/checkmarx-one.yml) | 针对 `main` 的 PR 打开、重开、更新 | Checkmarx SAST/SCA/KICS 扫描；需要 `CX_*` Secrets |
| [`codescan.yml`](../.github/workflows/codescan.yml) | `main` push/PR、每周定时 | CodeScan 扫描并上传 SARIF；需要 `CODESCAN_*` Secrets |

部署工作流只校验发布所需的输入、脚本语法和 release 构建，不会重复运行完整 Rust、前端或
端到端测试。发布实现与验收边界见
[`GITHUB_ACTIONS_DEPLOYMENT.md`](GITHUB_ACTIONS_DEPLOYMENT.md)。

## 4. 本地端到端测试

### 4.1 前置条件

- 安装与锁文件兼容的 Rust 工具链；CI 的集成测试使用 Rust 1.98.1。
- 本地端口 `7080`、`8080`、`9090`、`9091`、`9092`、`9093` 未被占用。
- 使用测试 fixture 的 Entry 与测试专用 Agent harness；不要把 harness 用作生产启动方式。
- 测试会创建本地输出报告；运行目录需要可写。

在三个终端分别启动 mock 目标、Proxy Entry 和 Agent harness：

```bash
# 终端 1：启动 HTTP、HTTP/2、TCP echo 和 UDP echo mock 服务
./run-tests.sh mock-target
```

```bash
# 终端 2：启动测试配置的 Proxy Entry
cargo run --package proxy-entry --bin proxy-entry -- \
  --config tests/fixtures/config/proxy-entry-integration.toml
```

```bash
# 终端 3：启动只为集成测试编译的 Agent harness
cargo run --package desktop-agent-be --features integration-test-harness \
  --bin desktop-agent-integration-harness -- \
  --config tests/fixtures/config/agent-integration.toml \
  --managed-proxy-address 127.0.0.1:8080
```

然后在第四个终端执行：

```bash
./run-tests.sh integration
```

脚本会在执行前要求确认；它默认使用 `AGENT_ADDR=127.0.0.1:7080` 和
`PROXY_ADDR=127.0.0.1:8080`，并用 release profile 构建 `integration-tests`。需要远程或
非默认地址时可覆盖环境变量：

```bash
AGENT_ADDR=10.0.0.10:7080 PROXY_ADDR=10.0.0.20:8080 \
  ./run-tests.sh integration
```

产品 Agent 不通过命令行接受 Proxy 地址；生产流量应在 Desktop Agent UI 完成登录与配置后
启动。`desktop-agent-integration-harness` 仅为 CI/本地端到端测试提供受控的
`--managed-proxy-address`。

### 4.2 Mock 目标服务

`mock-target` 默认启动以下本地服务：

| 服务 | 地址 | 用途 |
| --- | --- | --- |
| HTTP/1.1 | `127.0.0.1:9090` | `/health`、`/echo`、`/large`、JSON、Range 与网络波动响应 |
| HTTP/2 | `127.0.0.1:9093` | HTTP/2 多路复用与隧道回归用例 |
| TCP echo | `127.0.0.1:9091` | SOCKS5/TCP 转发与吞吐测试 |
| UDP echo | `127.0.0.1:9092` | SOCKS5 UDP ASSOCIATE、UDP relay 与吞吐测试 |

可使用 `cargo run -p integration-tests -- mock-target --help` 查看可覆写的端口参数。

## 5. 性能、吞吐与网络诊断

性能测试是环境相关的测量工具，不是固定阈值的 CI 门禁。一次结果至少应记录提交 SHA、
机器规格、OS、网络路径、Agent/Entry 配置、并发与 payload 大小，再与同条件基线比较。

所有如下命令都要求第 4 节的 Agent、Entry 和所需 mock 目标已启动，并在开始时要求确认。

| 命令 | 作用 | 默认/关键参数 |
| --- | --- | --- |
| `./run-tests.sh performance 100 60` | HTTP 和 SOCKS5 通用压力测试 | 并发、持续秒数 |
| `./run-tests.sh udp-performance 100 60 1200` | SOCKS5 UDP relay 性能 | UDP payload 字节数 |
| `./run-tests.sh tcp-performance 100 60 65536` | TCP relay 性能 | TCP payload 字节数 |
| `./run-tests.sh max-throughput 128 10 65536` | 分阶段扫描可持续端到端峰值吞吐 | 最大并发、每阶段秒数、payload |
| `./run-tests.sh quic-probe 20 cloudflare.com 3000` | 通过 SOCKS5 UDP 的 QUIC Version Negotiation 连通性探测 | 尝试次数、目标、超时毫秒 |
| `./run-tests.sh quic-performance 20 30 cloudflare.com 3000` | QUIC UDP/443 专项压力测试 | 并发、秒数、目标、超时 |

`max-throughput` 会分别比较 TCP/UDP 直连基线与端到端路径，并测试 TUN、HTTP Proxy、
SOCKS Proxy 和 UDP relay 可用的路径。它从 `START_CONCURRENCY`（默认 1）开始逐级增大，
直到 `MAX_CONCURRENCY`，只有失败率不超过 `MAX_FAILURE_RATE`（默认 1.0%）的阶段可参与
峰值评定。若需要确认 TUN 流量确实经过指定接口，设置 `TUN_INTERFACE`：

```bash
TUN_INTERFACE=utun8 START_CONCURRENCY=2 MAX_FAILURE_RATE=0.5 \
  ./run-tests.sh max-throughput 256 15 65536
```

常用目标覆盖变量：

```bash
TCP_TARGET_HOST=127.0.0.1 TCP_TARGET_PORT=9091 \
UDP_TARGET_HOST=127.0.0.1 UDP_TARGET_PORT=9092 \
./run-tests.sh tcp-performance 100 60 65536
```

QUIC 命令默认访问公共 Internet 目标，其结果会受到 DNS、目标服务、UDP 出口策略和网络丢包
影响，不应与完全离线的 mock 基准直接比较。

### 报告文件

性能命令默认在仓库根目录生成带时间戳的 HTML 报告，同时生成同名 JSON 与 Markdown 文件：

```text
performance-report-YYYYMMDD-HHMMSS.html
performance-report-YYYYMMDD-HHMMSS.json
performance-report-YYYYMMDD-HHMMSS.md
```

HTML 用于交互查看，JSON 用于机器比较与归档，Markdown 便于附在评审或故障记录中。使用
底层 CLI 时可通过 `--output` 指定报告文件名；完整可用子命令和参数以此为准：

```bash
cargo run --release -p integration-tests -- --help
```

该 CLI 还提供 `large-download`、`merge-max-throughput` 与 `render-max-throughput` 等高级
命令，分别用于 HTTP Range 大文件场景、合并分段吞吐 JSON，以及从已有 JSON 重新渲染报告。

## 6. Android 本地验证

Android CI 使用 JDK 17、Android SDK Platform 35、Build Tools 35.0.0 和 NDK
`28.2.13676358`。本地安装对应 SDK/NDK 后，可运行：

```bash
# Java/Kotlin 单元测试与 Android lint；跳过 Gradle 内部 Rust 构建
cd android-agent
./gradlew testDebugUnitTest lintDebug -PskipRustBuild=true --no-daemon --stacktrace

# native Rust 集成测试（从仓库根目录执行）
cargo test --manifest-path android-agent/native/Cargo.toml --locked
```

构建 JNI 库和 debug APK 的命令由 CI 负责验证；在本地需要配置 Android NDK，并使用
`cargo-ndk` 为 `arm64-v8a`、`armeabi-v7a`、`x86_64` 三个目标生成库。不要在没有 Android
工具链的普通 Rust 测试环境中强行运行这一步。

## 7. 常见问题与定位顺序

| 现象 | 优先检查项 |
| --- | --- |
| `connection refused` | mock、Entry、harness 是否已启动；端口 `9090/9091/9092/9093/8080/7080` 是否被占用或被防火墙阻断 |
| Agent 无法建立代理 | 使用的必须是测试 harness；确认 `--managed-proxy-address 127.0.0.1:8080` 和 fixture 配置 |
| UDP 测试失败 | 确认 UDP echo `:9092` 正在监听；检查本机防火墙与 Entry 的 UDP 转发日志 |
| Range/HTTP2 回归失败 | 保留 mock、Entry 和 Agent 三方日志；确认没有用生产配置替代 integration fixture |
| 性能明显波动 | 固定并发、payload、持续时间、网络路径和机器负载后重测；查看失败率及 P95/P99，而非只看平均值 |
| Android native 测试/构建失败 | 检查 JDK 17、Platform 35、NDK 版本与 Rust Android targets 是否匹配 CI |
| 部署布局检查失败 | 运行 `bash scripts/test-proxy-deployment-layout.sh`，按输出检查安装器、工作流、端口与路径约束 |

执行耗时或可能访问外网的压力测试前，应确认目标主机和网络资源在测试范围内；不要将高并发
默认参数直接用于未授权的生产公共服务。
