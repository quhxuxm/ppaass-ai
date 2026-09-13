# PPAASS 本地搭建指南

本文用于搭建单机开发或验收环境：Registry 监听本机回环地址，Proxy Entry 监听
`0.0.0.0:8080`，Desktop Agent 在登录后提供本地 HTTP/SOCKS5 入口。它不是生产部署手册；
生产使用 GitHub Actions、systemd 和 Caddy 的方式见
[GitHub Actions 部署文档](GITHUB_ACTIONS_DEPLOYMENT.md)。

## 1. 前置条件

| 项目 | 用途 |
| --- | --- |
| Rust 1.98.1 | 与主要 CI 和发布工作流一致的 Rust 工具链 |
| C/C++ 编译工具、`pkg-config`、OpenSSL 开发库 | 构建 Rust 网络与加密依赖 |
| Node.js 24 | 构建 Proxy Registry Vue 前端 |
| Node.js 22 + Tauri 平台依赖 | 运行 Desktop UI；macOS/Windows 使用各自系统依赖 |
| 浏览器或 Desktop UI | 注册、登录、密钥审批和启动受管 Agent |

Android 开发还需要 JDK 17、Android Platform 35、Build Tools 35.0.0 和 NDK
`28.2.13676358`；完整命令见[测试指南](TESTING.md#6-android-本地验证)。

确认工具链：

```bash
rustc --version
cargo --version
node --version
```

## 2. 获取依赖并构建

在仓库根目录执行：

```bash
# 构建所有 Rust workspace target，并严格使用 Cargo.lock
cargo build --workspace --all-targets --release --locked

# 构建 Registry Web 前端
cd proxy-registry/frontend
npm ci --no-audit --no-fund
npm run build
cd ../..
```

若只需运行本地控制面与数据面，可只构建相应 crate：

```bash
cargo build -p proxy-registry --release --locked
cargo build -p proxy-entry --release --locked
```

## 3. 启动本地 Proxy Registry

Registry 是账户、设备、密钥、授权和 Entry 目录的权威数据源。默认公开 API 监听
`127.0.0.1:8787`，Entry 控制 API 单独监听 `127.0.0.1:8797`。两者都只用于本地开发；
生产环境应由 Caddy 在 HTTPS 后暴露。

先创建仅供本地开发的密钥和共享 Token。Control Token 必须同时传给 Registry 与 Entry；
密钥加密主密钥一旦写入一个已有数据库就不能改变。

```bash
umask 077
mkdir -p data

export PPAASS_PROXY_REGISTRY_BOOTSTRAP_ADMIN_PASSWORD='replace-with-a-strong-password'
export PPAASS_PROXY_REGISTRY_KEY_ENCRYPTION_SECRET='replace-with-at-least-32-random-bytes'
export PPAASS_PROXY_REGISTRY_CONTROL_TOKEN='replace-with-at-least-32-random-bytes'

printf '%s' "$PPAASS_PROXY_REGISTRY_CONTROL_TOKEN" > data/proxy-control-token
chmod 600 data/proxy-control-token

cargo run -p proxy-registry -- \
  --listen 127.0.0.1:8787 \
  --control-listen 127.0.0.1:8797
```

首次针对空数据库启动时会创建用户名为 `admin` 的管理员。之后修改
`PPAASS_PROXY_REGISTRY_BOOTSTRAP_ADMIN_PASSWORD` 不会覆盖已有管理员密码。默认 SQLite 文件
位于 `data/proxy-users.sqlite3` 与 `data/proxy-access.sqlite3`；不要让 Entry 直接打开它们。

可在浏览器打开 `http://127.0.0.1:8787` 检查管理页面；健康检查为：

```bash
curl --fail http://127.0.0.1:8787/healthz
curl --fail http://127.0.0.1:8797/control/v1/health \
  -H "Authorization: Bearer $PPAASS_PROXY_REGISTRY_CONTROL_TOKEN"
```

Registry 本地开发、API 与管理员流程详见
[proxy-registry/README.md](../proxy-registry/README.md)。

## 4. 配置并启动本地 Proxy Entry

生产模板 [`config/proxy-entry.toml`](../config/proxy-entry.toml) 使用生产路径，不应原样用于
本机开发。可在 `data/proxy-entry-local.toml` 创建以下最小配置：

```toml
listen_addr = "0.0.0.0:8080"
entry_id = "entry-local"
advertised_address = "127.0.0.1:8080"
registry_url = "http://127.0.0.1:8797"
registry_control_token_path = "data/proxy-control-token"
authorization_database_path = "data/proxy-entry-authorization.sqlite3"

# 开发机上可保留默认系统路由；与本机 TUN 共存时可改为 "auto"。
# outbound_interface = "auto"
```

启动 Entry：

```bash
cargo run -p proxy-entry -- --config data/proxy-entry-local.toml
```

Entry 在同一数值端口同时监听 TCP 与原生 UDP。它会使用 Control Token 注册自身、拉取公开
授权快照并订阅变更；首份完整快照成功前会拒绝 Agent 认证。`authorization_database_path`
仅保存公开密钥、权限和状态的 last-known-good 副本，不能替代 Registry 数据库。

本机防火墙、容器网络或远端实验环境都必须同时放行 Entry 端口的 TCP 与 UDP。生产中的端口、
实例数量、systemd 和防火墙处理见[部署文档](GITHUB_ACTIONS_DEPLOYMENT.md)。

## 5. 登录并启动 Desktop Agent

1. 打开 Registry 页面，注册普通账号；管理员以 `admin` 登录后，按界面流程批准该账号的
   密钥申请并设置有效期。
2. 在 [`config/agent.toml`](../config/agent.toml) 中确认 `proxy_registry_url` 指向本地 Registry：

   ```toml
   listen_addr = "127.0.0.1:10080"
   proxy_registry_url = "http://127.0.0.1:8787"
   transport_mode = "udp" # 也可为 auto 或 tcp
   ```

3. 启动 Desktop UI 并在 UI 中登录：

   ```bash
   cd desktop-agent-ui
   npm ci
   npm run tauri dev
   ```

4. 在 UI 中启动 Agent。登录后的原生后端领取受管用户名、私钥、Agent access token 和
   已分配的 Entry 地址；它们不会暴露给 Vue WebView，也不应手动复制进仓库。

产品 `desktop-agent` 命令行不会接受旧的公开 Proxy 地址参数，也不会在未认证状态下启动
正常代理流量。若目的是集成测试，使用测试专用 harness，见[测试指南](TESTING.md#4-本地端到端测试)。

## 6. 验证代理

Agent 启动后，使用 `listen_addr`（上例为 `127.0.0.1:10080`）验证本地入口：

```bash
curl -x http://127.0.0.1:10080 https://example.com/
curl --socks5-hostname 127.0.0.1:10080 https://example.com/
```

在 Desktop UI 中还应确认当前 Entry 在线、密钥状态有效且同步没有错误。需要验证 UDP、
TUN、HTTP/2、Range、性能或 QUIC，请按[测试指南](TESTING.md)启动 mock target 与
测试专用 Agent harness，而不是用公共网站的单次 curl 结果判断。

## 7. TUN 与平台权限

- Desktop TUN 会创建虚拟网卡、安装路由并捕获 DNS 流量，但不会改写系统 DNS 服务器设置。
- macOS 在 `[tun] enabled = true` 且 `macos_helper_enabled = true` 时可通过
  `start-agent.sh` 或 `start-agent.command` 安装 helper service；卸载使用：

  ```bash
  ./scripts/uninstall-tun-helper-unix.sh
  ```

- Windows 首次 TUN 启动可由 `start-agent.bat` 创建最高权限计划任务，可能出现一次 UAC。
- Android 使用 `VpnService` 与 JNI native Agent；请阅读
  [Android Agent 文档](../android-agent/README.md)。

TUN、DNS、direct-access、QUIC 策略与抓包边界见
[项目学习导览](PROJECT_WALKTHROUGH.md) 和
[技术架构与实现细节](TECHNICAL_DETAILS.md)。

## 8. 常见问题

| 现象 | 检查方式 |
| --- | --- |
| Registry 无法启动 | 三个 `PPAASS_PROXY_REGISTRY_*` 环境变量是否存在；`data/` 是否可写；已有数据库的密钥加密主密钥是否保持原值。 |
| Entry 认证全部被拒绝 | 确认 Entry 能访问 `registry_url`、Control Token 内容完全匹配、首份授权快照已经完成。 |
| Agent 登录后仍无法代理 | 检查账号/密钥是否获批且未过期、Entry 是否在线、UI 同步状态以及 `listen_addr` 端口。 |
| TCP 可用而 UDP 不可用 | 检查 Entry 端口的 UDP 防火墙/云安全组、`transport_mode` 和 UDP relay 日志。 |
| TUN 启动失败或控制连接回流 | 检查管理员权限、helper/计划任务与物理出口绑定；不要通过手工改系统 DNS 规避问题。 |
| HTTPS Registry 自检失败 | 开发环境使用回环 HTTP；生产应检查 Caddy、证书、443 可达性和 Registry `/healthz`、`/control/v1/health`。 |

## 9. 下一步

- [README](../README.md)：架构概览、配置要点、快速入口和文档导航。
- [功能需求与现有能力](REQUIREMENTS.md)：确认系统支持的业务范围。
- [技术架构与实现细节](TECHNICAL_DETAILS.md)：协议、算法、数据库和时序图。
- [测试指南](TESTING.md)：运行 CI 等价检查、集成测试和性能测试。
- [部署文档](GITHUB_ACTIONS_DEPLOYMENT.md)：将本地流程迁移为生产 GitHub Actions 发布。
