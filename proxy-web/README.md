# Proxy Web 用户中心

`proxy-web` 是独立监听端口的账号与 Proxy 用户管理服务：

- Axum 提供注册、登录、用户自助和管理员 API。
- Vue 3 + PrimeVue 4 提供普通用户中心与管理员控制台。
- 本地密码使用 Argon2id 哈希；登录态使用服务端不透明会话、HttpOnly Cookie 和 CSRF Token。
- RSA 私钥使用部署主密钥 AES-256-GCM 加密后写入数据库，公钥与私钥按版本原子更新。
- `proxy-user-store::UserRepository`、`AccountRepository` 和 `AccessLogRepository` 是数据库无关接口；当前适配器使用 SQLite。
- Proxy 与 Web 可读取同一个 SQLite 文件；全部服务日志使用 `tracing`，不会记录密码、Cookie 或私钥。

## 首次启动与管理员账号

系统不再使用“管理员 Token”。首次打开一个没有管理员的数据库时，通过环境变量创建真实管理员账号：

```bash
export PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_USERNAME="admin"
export PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_PASSWORD="replace-with-a-strong-password"
export PPAASS_PROXY_WEB_KEY_ENCRYPTION_SECRET="replace-with-at-least-32-random-bytes-and-keep-it-stable"

RUST_LOG=proxy_web=debug,proxy_user_store=debug,tower_http=info \
  cargo run -p proxy-web
```

管理员用户名默认是 `admin`。管理员一旦存在，bootstrap 用户名和密码不会再次创建或覆盖账号。不要把密码写进仓库或命令行参数。

`PPAASS_PROXY_WEB_KEY_ENCRYPTION_SECRET` 至少 32 字节，并且必须在服务重启和迁移后保持一致；丢失它将无法解密已托管的私钥。生产环境应从 Secret Manager 注入并单独备份。

## GitHub Actions 部署

手动运行 `.github/workflows/deploy-proxy.yml` 会同时构建并部署 Proxy、Proxy Web 和 Vue
静态资源。必须为 workflow 配置以下 GitHub Actions 配置：

- Secret `PPAASS_WEB_ADMIN_PASSWORD`：首次创建 `admin` 使用的密码。
- Secret `PPAASS_DEPLOY_SSH_KNOWN_HOSTS`：部署服务器经过核验的 SSH `known_hosts`
  记录；workflow 会强制校验主机公钥，拒绝未知或发生变化的服务器。
- Variable `PPAASS_WEB_PUBLIC_HOST`：对外服务的 DNS 名称或 IPv4 地址，不包含协议和端口。

workflow 只在远端数据库没有启用管理员时使用管理员密码，不会覆盖已有管理员的密码。
服务器合法更换 SSH 主机密钥时，应先通过独立渠道核验新指纹，再更新
`PPAASS_DEPLOY_SSH_KNOWN_HOSTS`。
生产环境由 Caddy 2.11.4 或更高版本监听 TCP/443，再反向代理到只监听
`127.0.0.1:8787` 的 Axum 服务。workflow 会检查服务器上的 Caddy 版本；未安装或版本
过低时，会校验官方发布包的 SHA-512 后自动安装。Proxy Web 始终使用 Secure Cookie，
不会把回环 HTTP 端口暴露到公网。

当 `PPAASS_WEB_PUBLIC_HOST` 是公网 IPv4 地址时，Caddy 会向 Let's Encrypt 申请
`shortlived` IP 证书，并通过 TLS-ALPN-01 在 TCP/443 上完成验证。Caddy 会在证书到期
前自动续期并加载新证书，无需人工更新或重新部署。IP 证书的 160 小时有效期是
Let's Encrypt 的设计；正常运行的 Caddy 会持续自动管理它。HTTP-01 已禁用，因此申请
和续期不会占用或中断 TCP/80，Proxy 原有的 TCP/UDP 监听可继续使用 80 端口。Caddy
的账号、证书和续期状态持久化在 `/var/lib/ppaass-caddy`，部署时不会清空该目录。

不需要在 GitHub 中保存 TLS 证书或私钥，也不再使用
`PPAASS_WEB_TLS_CERTIFICATE`、`PPAASS_WEB_TLS_PRIVATE_KEY` 这类 Secret。服务器和云
安全组需要允许公网访问 TCP/443，并允许 Caddy 访问 Let's Encrypt 的 ACME 服务；
workflow 会通过系统信任链访问公开的 `/healthz`，以验证证书和反向代理均可用。

私钥加密主密钥首次部署时生成在远端部署目录的
`.secrets/proxy-web-key-encryption-secret`，不会打入构建包。Proxy Web 会把认证校验信封
存入 SQLite 元数据，并在每次启动时校验当前主密钥；已有 legacy 数据库可以首次接入，
错误主密钥则无法通过启动检查。必须将数据库和主密钥成对备份与迁移，避免已有托管
私钥无法解密。

默认配置：

- 对外地址：`https://<PPAASS_WEB_PUBLIC_HOST>`（Caddy TCP/443）
- Axum 回环地址：`http://127.0.0.1:8787`
- Caddy 持久化目录：`/var/lib/ppaass-caddy`
- SQLite：`data/proxy-users.sqlite3`
- 首次导入：`config/local/users.toml`
- Vue 构建目录：`proxy-web/frontend/dist`
- GitHub 部署显式开放普通用户注册，并强制使用 Secure Cookie

可通过以下环境变量显式覆盖注册与 Cookie 行为：

```bash
export PPAASS_PROXY_WEB_ALLOW_REGISTRATION="true"
export PPAASS_PROXY_WEB_SECURE_COOKIES="true"
```

Axum 本身只提供 HTTP，默认只允许监听回环地址。本地开发或手动启动时继续使用：

```bash
cargo run -p proxy-web -- \
  --listen 127.0.0.1:8787
```

生产部署不要让 Axum 直接持有证书或监听 443，应保持回环监听并由 Caddy 提供公网
HTTPS。`--allow-insecure-remote` 只供自定义拓扑中受信 TLS 反向代理后的明文内网链路
使用，不能用于公网。

## Vue 本地开发

前端开发服务器会把 `/api` 和 `/healthz` 转发给 Axum：

```bash
cd proxy-web/frontend
npm install
npm run dev
```

浏览器打开 `http://127.0.0.1:5173`。如 Axum 使用其他地址，可通过
`PPAASS_PROXY_WEB_API_TARGET` 修改 Vite 的代理目标。

也可以先运行 `npm run build`，再访问 `http://127.0.0.1:8787`；Axum 会直接托管 `dist`。

## Google 与微信登录

第三方登录只有在对应变量完整配置后才会出现在页面中。

Google：

```bash
export PPAASS_GOOGLE_CLIENT_ID="..."
export PPAASS_GOOGLE_CLIENT_SECRET="..."
export PPAASS_GOOGLE_REDIRECT_URI="https://example.com/api/v1/auth/oauth/google/callback"
```

微信开放平台网站应用：

```bash
export PPAASS_WECHAT_APP_ID="..."
export PPAASS_WECHAT_APP_SECRET="..."
export PPAASS_WECHAT_REDIRECT_URI="https://example.com/api/v1/auth/oauth/wechat/callback"
```

Google 流程使用 authorization code、state 和 PKCE；微信流程使用 `snsapi_login` 与 state。外部身份以 Google `sub`、微信 `unionid`（没有时使用 `openid`）为稳定标识。首次第三方登录只创建普通账号，不会创建 Proxy 配置或密钥；用户需要提交密钥申请，管理员审批并指定有效期后，服务端才会生成并托管密钥对。

## API

登录成功后浏览器接收 HttpOnly 会话 Cookie。修改请求还必须发送登录或 session 响应中的
`csrf_token`：

```text
X-CSRF-Token: <csrf_token>
```

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/healthz` | 健康检查 |
| `GET` | `/api/v1/auth/providers` | 查询本地注册及 OAuth 可用状态 |
| `POST` | `/api/v1/auth/register` | 创建普通账号（不生成 Proxy 配置或密钥） |
| `POST` | `/api/v1/auth/login` | 用户名密码登录 |
| `POST` | `/api/v1/auth/logout` | 退出登录 |
| `GET` | `/api/v1/auth/oauth/{provider}/start` | 创建 OAuth 登录请求 |
| `GET` | `/api/v1/auth/oauth/{provider}/callback` | OAuth 回调 |
| `GET` | `/api/v1/session` | 查询当前登录态并取得 CSRF Token |
| `GET` | `/api/v1/me` | 查询账号、Proxy 配置、密钥状态和待审批申请 |
| `GET` | `/api/v1/me/private-key` | 读取自己的有效公钥和私钥 |
| `POST` | `/api/v1/me/rotate-key` | 在现有密钥有效且有权限时直接轮换自己的密钥 |
| `GET` | `/api/v1/me/key-request` | 查询自己的待审批密钥申请 |
| `POST` | `/api/v1/me/key-requests` | 在缺少密钥或密钥已过期时提交密钥申请 |
| `GET` | `/api/v1/me/access-records` | 查询自己的近期 Proxy 访问记录 |
| `GET` | `/api/v1/admin/users` | 管理员列出所有账号及 legacy 用户 |
| `POST` | `/api/v1/admin/users` | 管理员创建已批准用户并生成密钥，必须指定未来有效期 |
| `GET/PATCH/DELETE` | `/api/v1/admin/users/{username}` | 管理员查询、修改或删除用户（密钥字段始终脱敏） |
| `POST` | `/api/v1/admin/users/{username}/rotate-key` | 管理员轮换仍有效的密钥（不返回密钥材料） |
| `GET` | `/api/v1/admin/key-requests` | 管理员列出待审批密钥申请 |
| `POST` | `/api/v1/admin/key-requests/{request_id}/approve` | 批准申请并生成密钥，必须指定未来有效期 |
| `POST` | `/api/v1/admin/key-requests/{request_id}/reject` | 拒绝密钥申请 |
| `GET/PATCH` | `/api/v1/admin/access-log-settings` | 查询或修改访问记录保留天数 |

管理员 API 只能触发密钥生成或轮换。列表、详情、创建、更新和轮换响应都使用独立的
脱敏 DTO，不包含 `public_key_pem`、`private_key_pem` 或 `credentials`；管理员私钥读取
路由不存在。只有用户本人登录后，才能通过 `/api/v1/me` 查看自己的公钥信息，并通过
`/api/v1/me/private-key` 读取自己的公私钥。私钥响应带 `Cache-Control: no-store`。

## 密钥申请、审批与有效期

本地注册和 OAuth 首次登录只创建账号。没有 Proxy 配置或密钥已经过期时，用户通过
`POST /api/v1/me/key-requests` 提交申请；同一账号同时只能有一条 `pending` 申请，
重复或并发提交会幂等返回同一条申请。管理员批准时必须给出严格晚于当前时间的
`expires_at`，RSA 密钥只在服务端生成，私钥加密入库且不会出现在管理员响应中。
申请被拒绝后，用户可以重新提交。

`GET /api/v1/me` 的 `key_state` 为 `missing`、`active`、`expired` 或 `disabled`。
只有 `active` 状态才返回公钥，并允许用户读取私钥。普通用户直接轮换密钥需要同时满足：

- Web 账号处于启用状态；
- Proxy 用户配置已启用；
- 尚未到达 `expires_at`；
- 拥有 `key.rotate` 权限。

过期或缺失密钥不能通过用户或管理员的直接轮换接口恢复，也不能通过管理员 PATCH
清空有效期或把过期时间改到未来绕过审批；必须重新提交并批准密钥申请。管理员直接
创建用户仍属于已批准流程，`expires_at` 必填且必须严格晚于当前时间，额外权限会与
四项基础权限合并。`users.toml` 导入的 legacy 用户不参与 Web 密钥申请流程。

公钥/私钥轮换只影响后续认证；已经建立的 TCP 连接或 UDP 会话不会被主动断开。

## 访问记录与保留期

`GET /api/v1/me/access-records` 只按当前登录账号关联的 Proxy 用户名查询，不接受指定
其他用户名。可选参数 `since` 会被限制在当前保留期内，`limit` 必须在 `1..=1000`。
响应只包含 `target_host`、`target_port`、`protocol`、`accessed_at` 和顶层的
`retention_days`，不会返回用户名或数据库记录 ID。

默认保留期为 7 天。管理员可通过
`PATCH /api/v1/admin/access-log-settings` 将其设置为 `1..=365` 天；修改成功后会立即
清理超出新保留期的历史记录。修改请求需要有效的管理员会话和 CSRF Token。

## 权限

当前内置权限 code：

- `proxy.connect.tcp`
- `proxy.connect.udp`
- `key.private.read`
- `key.rotate`

本地注册或 OAuth 账号的密钥申请获批后，以及管理员直接创建 Web 普通用户时，Proxy
配置都会强制拥有以上四项基础能力。管理员创建用户时传入的其他权限会与基础能力合并；
管理员后续通过 PATCH 更新权限时，也不能移除这四项能力。

Proxy 会在认证及 CONNECT/原生 UDP 边界实际执行 TCP/UDP 权限，不只是把权限展示在页面上。

## Proxy 与 users.toml 兼容

原有模式完全保留：

```toml
# 不配置 users_database_path
users_path = "config/local/users.toml"
```

共享数据库模式：

```toml
users_path = "config/local/users.toml"
users_database_path = "data/proxy-users.sqlite3"
```

数据库模式首次启动时会完整校验并事务导入 `users.toml`。导入后 SQLite 是唯一运行时数据源，不与 TOML 双写；数据库已有用户时会记录跳过状态，不覆盖已有数据。

TOML 导入用户只有历史公钥，不可能恢复原私钥，因此在管理端标记为 `legacy`。这类
public-only 记录保持原有默认 TCP/UDP 权限，不会因为 Web 普通用户策略而自动增加
`key.private.read` 或 `key.rotate`。由于它没有可登录并领取密钥的 Web 账号，管理端
会拒绝为 legacy 记录轮换密钥，避免生成一套无人能取得的私钥。未配置
`users_database_path` 时，原 TOML 解析及默认 TCP/UDP 权限行为保持不变。

在 Unix 上，SQLite 主文件、WAL 和共享内存文件设为 `0600`。Proxy 与 Web 应以同一操作系统用户运行并使用完全相同的数据库路径。

两个业务层只依赖数据库无关 Repository。将来增加 PostgreSQL 等数据库时，应新增适配器并在启动阶段选择实现，无需修改 Proxy 认证或 Axum handler。
