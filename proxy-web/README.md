# Proxy Web 用户中心

`proxy-web` 是独立监听端口的账号与 Proxy 用户管理服务：

- Axum 提供注册、登录、用户自助和管理员 API。
- Vue 3 + PrimeVue 4 提供普通用户中心与管理员控制台。
- 本地密码使用 Argon2id 哈希；登录态使用服务端不透明会话、HttpOnly Cookie 和 CSRF Token。
- RSA 私钥使用部署主密钥 AES-256-GCM 加密后写入数据库，公钥与私钥按版本原子更新。
- `proxy-user-store::UserRepository`、`AccountRepository`、`AccessLogRepository` 和
  `AgentDeviceAuthorizationRepository` 是数据库无关接口；当前适配器使用 SQLite。
- Web 读写用户 SQLite，Proxy 仅只读该库；访问记录使用单独的共享 SQLite。全部服务
  日志使用 `tracing`，不会记录密码、Cookie 或私钥。

## 首次启动与管理员账号

系统不再使用“管理员 Token”。首次打开一个没有管理员的数据库时，通过环境变量创建真实管理员账号：

```bash
export PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_PASSWORD="replace-with-a-strong-password"
export PPAASS_PROXY_WEB_KEY_ENCRYPTION_SECRET="replace-with-at-least-32-random-bytes-and-keep-it-stable"

RUST_LOG=proxy_web=debug,proxy_user_store=debug,tower_http=info \
  cargo run -p proxy-web
```

根管理员用户名固定为 `admin`；如果仍设置
`PPAASS_PROXY_WEB_BOOTSTRAP_ADMIN_USERNAME`，它也只能是 `admin`。其他管理员不能阻止
系统补建根管理员。`admin` 一旦存在，bootstrap 密码不会覆盖账号。不要把密码写进仓库
或命令行参数。

`PPAASS_PROXY_WEB_KEY_ENCRYPTION_SECRET` 至少 32 字节，并且必须在服务重启和迁移后保持一致；丢失它将无法解密已托管的私钥。生产环境应从 Secret Manager 注入并单独备份。

## GitHub Actions 部署

手动运行 `.github/workflows/deploy-proxy.yml` 会同时构建并部署 Proxy、Proxy Web 和 Vue
静态资源。必须为 workflow 配置以下 GitHub Actions 配置：

部署 job 会绑定 workflow 输入所选的同名 GitHub Environment：`production`、`dev` 或
`qa`。下面的 Secrets 和 Variables 必须分别配置在对应 Environment 中，不应使用一套
仓库级凭据跨环境复用；Environment protection rules 也会在读取该环境凭据前生效。

- 对应环境的 SSH Secrets：`PRODUCTION_REMOTE_HOST/USER/PASSWORD`、
  `DEV_REMOTE_HOST/USER/PASSWORD` 或 `QA_REMOTE_HOST/USER/PASSWORD`。
- Secret `DEPLOY_FOLDER`：该环境服务器上的专用上传暂存子目录。
- Secret `PPAASS_WEB_ADMIN_PASSWORD`：首次创建 `admin` 使用的密码。
- Secret `PPAASS_DEPLOY_SSH_KNOWN_HOSTS`：部署服务器经过核验的 SSH `known_hosts`
  记录；workflow 会强制校验主机公钥，拒绝未知或发生变化的服务器。
- Variable `PPAASS_WEB_PUBLIC_HOST`：对外服务的 DNS 名称或 IPv4 地址，不包含协议和端口。

workflow 只在远端数据库没有启用的根管理员 `admin` 时使用管理员密码，不会覆盖已有
`admin` 的密码；其他管理员账号不能替代根管理员。
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

私钥加密主密钥首次部署时生成在
`/var/lib/ppaass/secrets/proxy-web-key-encryption-secret`，不会打入构建包。Proxy Web 会把认证校验信封
存入 SQLite 元数据，并在每次启动时校验当前主密钥；已有 legacy 数据库可以首次接入，
错误主密钥则无法通过启动检查。必须将数据库和主密钥成对备份与迁移，避免已有托管
私钥无法解密。

Proxy TCP/Yamux 传输身份同样不进入仓库或 GitHub Secrets。服务器首次部署时由 OpenSSL
原子生成一把持久的 3072 位 PKCS#8 RSA 私钥，保存为
`/var/lib/ppaass/identity/proxy-identity-private.pem`（仅 Proxy UID、`0600`）；每次部署
都从它重新派生 SPKI 公钥给 Proxy Web 只读。后续部署复用同一私钥，不会静默轮换 Agent
已经固定校验的服务端身份。

`DEPLOY_FOLDER` 只作为 root 使用的上传暂存目录；它必须是专用子目录（例如
`/root/ppaass-upload`），即使位于 `/root` 下也不会成为 systemd 服务的工作目录。
workflow 将 root 拥有的二进制、脚本和配置安装到
`/opt/ppaass`，并使用两个 UID 不同的无登录系统用户运行服务：

- Proxy 使用 `ppaass-proxy` 用户，只保留绑定低端口所需的
  `CAP_NET_BIND_SERVICE`，并通过 systemd `InaccessiblePaths` 阻止读取 Web Secret。
- Proxy Web 使用 `ppaass-proxy-web` 用户且不持有 capability。Web Secret 由 root
  拥有且只给 `ppaass-proxy-web` 组读权限，因此 Proxy UID 无法通过文件权限或
  `/proc/<pid>`/ptrace 读取 Web 主密钥或管理员密码。
- 用户/账号/密钥数据库位于 `/var/lib/ppaass/users`。目录由 Web UID 拥有并使用
  `ppaass-user-readers` 组和 `2750`；数据库、WAL、SHM 与 rollback journal 使用
  `ppaass-proxy-web:ppaass-user-readers` 和 `0640`。Proxy 只拥有该组的读/执行权限，
  并同时通过 SQLite read-only/query-only 模式及 systemd `ReadOnlyPaths` 禁止写入。
- 访问记录单独存放在 `/var/lib/ppaass/access`。该目录使用受限
  `ppaass-access` 共享组和 `2770`，数据库及 sidecar 使用 `0660`。Proxy 需要写入
  访问次数，Web 需要查询和执行保留期清理，因此只有这个不含账号、密钥或认证资料的
  数据库允许两个 UID 读写。

首次采用新目录布局时，workflow 会在两个服务停止后，把旧
`DEPLOY_FOLDER/data/proxy-users.sqlite3`，或上一版固定目录中的
`/var/lib/ppaass/data/proxy-users.sqlite3`，连同 WAL/SHM/journal 一起迁移到
`/var/lib/ppaass/users`，并迁移旧 `.secrets` 中的加密主密钥。若多个旧位置同时存在，
或旧位置和新位置同时存在用户数据库，workflow 会明确失败，不会静默选择一份数据。
用户数据库会原地调整为 Web 拥有的 `0640`，不会复制或重建。

部署会先启动 Proxy Web。它完成用户 schema 迁移，并把旧用户数据库里的历史访问
记录与保留期设置幂等迁移到新的访问记录数据库；核对导入结果后会清空主库旧记录并
截断对应 WAL，避免访问历史继续残留在用户库。`/healthz` 成功后才启动只读用户库的
Proxy。systemd 冷启动也会让 Proxy 等待 Web 健康，避免 Proxy 在 schema 迁移前打开
数据库。

默认配置：

- 对外地址：`https://<PPAASS_WEB_PUBLIC_HOST>`（Caddy TCP/443）
- Axum 回环地址：`http://127.0.0.1:8787`
- 服务运行目录：`/opt/ppaass`
- Caddy 持久化目录：`/var/lib/ppaass-caddy`
- 用户 SQLite：`/var/lib/ppaass/users/proxy-users.sqlite3`
- 访问记录 SQLite：`/var/lib/ppaass/access/proxy-access.sqlite3`
- Proxy 传输身份私钥：`/var/lib/ppaass/identity/proxy-identity-private.pem`
- Proxy Web 可读的传输身份公钥：`/var/lib/ppaass/identity/proxy-identity-public.pem`
- Proxy Web Secret：`/var/lib/ppaass/secrets`
- 服务日志：`/var/log/ppaass/proxy`、`/var/log/ppaass/proxy-web`
- Vue 构建目录：`proxy-web/frontend/dist`
- GitHub 部署显式开放普通用户注册，并强制使用 Secure Cookie

可通过以下环境变量显式覆盖注册与 Cookie 行为：

```bash
export PPAASS_PROXY_WEB_ALLOW_REGISTRATION="true"
export PPAASS_PROXY_WEB_SECURE_COOKIES="true"
# 仅当 Axum 回环监听且前方是受信反向代理时启用，用于按真实客户端 IP 限频。
export PPAASS_PROXY_WEB_TRUST_PROXY_HEADERS="true"
```

Axum 本身只提供 HTTP，默认只允许监听回环地址。本地开发或手动启动时继续使用：

```bash
mkdir -p data
umask 077
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 \
  -out data/proxy-identity-private.pem
openssl pkey -in data/proxy-identity-private.pem -pubout \
  -out data/proxy-identity-public.pem
cargo run -p proxy-web -- \
  --listen 127.0.0.1:8787 \
  --proxy-identity-public-key data/proxy-identity-public.pem
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

## API

登录成功后浏览器接收 HttpOnly 会话 Cookie。修改请求还必须发送登录或 session 响应中的
`csrf_token`：

```text
X-CSRF-Token: <csrf_token>
```

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/healthz` | 健康检查 |
| `GET` | `/api/v1/auth/providers` | 查询本地注册是否启用 |
| `POST` | `/api/v1/auth/register` | 创建普通账号（不生成 Proxy 配置或密钥） |
| `POST` | `/api/v1/auth/login` | 用户名密码登录 |
| `POST` | `/api/v1/auth/logout` | 退出登录 |
| `POST` | `/api/v1/agent/login` | 原生 Agent 密码认证，一次返回角色、权限、密钥和持续同步凭据 |
| `GET` | `/api/v1/agent/me` | Agent 使用 Bearer 凭据定期刷新账号状态和权限 |
| `POST` | `/api/v1/agent/device-authorizations` | Agent 创建浏览器设备登录 challenge |
| `POST` | `/api/v1/agent/device-authorizations/token` | Agent 限频轮询并一次性领取账户配置和密钥 |
| `POST` | `/api/v1/agent/device-authorizations/inspect` | 已登录用户核对设备登录请求 |
| `POST` | `/api/v1/agent/device-authorizations/approve` | 已登录用户批准设备登录 |
| `POST` | `/api/v1/agent/device-authorizations/deny` | 已登录用户拒绝设备登录 |
| `GET` | `/api/v1/session` | 查询当前登录态并取得 CSRF Token |
| `GET` | `/api/v1/me` | 查询账号、Proxy 配置、密钥状态和待审批申请 |
| `PUT` | `/api/v1/me/password` | 校验当前密码并修改登录密码；成功后撤销该账号全部 Web 会话 |
| `GET` | `/api/v1/me/private-key` | 原生 Agent 登录时领取自己的有效连接凭据；Web 控制台不展示或调用 |
| `POST` | `/api/v1/me/rotate-key` | 在现有密钥有效且有权限时直接轮换自己的密钥 |
| `GET` | `/api/v1/me/key-request` | 查询自己的待审批密钥申请 |
| `POST` | `/api/v1/me/key-requests` | 在缺少密钥或密钥已过期时提交申请；可带 `{"message":"..."}` 留言 |
| `GET` | `/api/v1/me/access-records` | 查询自己的近期 Proxy 访问记录 |
| `GET` | `/api/v1/admin/users` | 管理员列出所有账号及 legacy 用户 |
| `POST` | `/api/v1/admin/users` | 管理员创建已批准用户并生成密钥，必须指定未来有效期 |
| `GET/PATCH/DELETE` | `/api/v1/admin/users/{username}` | 管理员查询、修改或删除用户（删除前必须先停用，密钥字段始终脱敏） |
| `POST` | `/api/v1/admin/users/{username}/rotate-key` | 管理员轮换仍有效的密钥（不返回密钥材料） |
| `GET` | `/api/v1/admin/key-requests` | 管理员列出待审批密钥申请 |
| `POST` | `/api/v1/admin/key-requests/{request_id}/approve` | 批准申请并生成密钥，必须指定未来有效期 |
| `POST` | `/api/v1/admin/key-requests/{request_id}/reject` | 拒绝密钥申请 |
| `GET/PATCH` | `/api/v1/admin/access-log-settings` | 查询或修改访问记录保留天数 |

管理员 API 只能触发密钥生成或轮换。列表、详情、创建、更新和轮换响应都使用独立的
脱敏 DTO，不包含 `public_key_pem`、`private_key_pem` 或 `credentials`。Web 控制台不再
提供私钥显示、复制或下载面板；原生 Agent 使用已认证的本人接口领取连接凭据，并在本机
受限目录中直接应用。密钥响应带 `Cache-Control: no-store`。

固定根管理员 `admin` 不能被停用、降级或删除。其他普通用户和管理员都可以被停用，
但只有 `status=disabled` 的 Web 账号才能删除；没有 Web 账号的 legacy profile 必须先
设置 `enabled=false`。这些约束同时由管理界面和存储事务执行，不能通过直接调用 API
绕过。

## Agent 原生登录与权限同步

Desktop、Windows 和 Android Agent 的登录页直接向配置文件中的 Proxy Web 地址发送
`POST /api/v1/agent/login`，地址不会展示给用户。该原生端点拒绝带浏览器 `Origin` 的
请求，不创建 Web Cookie；认证成功后一次返回当前账号角色、Proxy profile 权限、同一
版本的连接密钥，以及仅供 Agent 使用的 `agent_access_token`。

Agent access token 使用部署主密钥派生的独立 AES-256-GCM key 加密认证，服务重启后仍可
验证。Agent 把 token 与受管私钥一起保存到仅当前系统用户可读的本机凭据目录，绝不传给
前端脚本或写入日志。登录后立即、随后按服务端返回的
`refresh_after_seconds`（当前 300 秒）调用：

```http
GET /api/v1/agent/me
Authorization: Bearer <agent_access_token>
```

响应返回最新角色、账号状态、`key_state`、权限和滚动更新的 token。权限变更会直接刷新
Agent 界面和 Rust/原生命令层约束，不要求退出或重启。临时网络错误、5xx、401 均不会
清除登录、私钥或停止代理；Agent 保留最后一次成功验证的权限并显示同步错误。账号被
停用或密钥过期时，接口仍返回 200 和权威状态，Agent 保留登录但显示明确错误。连续
30 天未成功刷新而导致 token 过期时，需要重新登录才能恢复权限同步。

## 设备授权 API（可选）

服务端仍提供一次性设备授权 API。需要该流程的原生客户端先向配置好的 Proxy Web 地址
发送：

```http
POST /api/v1/agent/device-authorizations
Content-Type: application/json

{"platform":"android","client_name":"Alice Android"}
```

响应包含 256 位随机 `device_code`、12 字符短码、相对验证地址、600 秒有效期和 5 秒
最小轮询间隔：

```json
{
  "device_code": "<base64url>",
  "user_code": "ABCD-EFGH-JKLM",
  "verification_uri": "/#agent-authorize",
  "verification_uri_complete": "/#agent-authorize=ABCD-EFGH-JKLM",
  "expires_in": 600,
  "interval": 5
}
```

Agent 使用自身配置的 Proxy Web base URL 拼接 `verification_uri_complete`，并交给系统
浏览器打开。用户使用本地账号密码完成网页登录，然后在独立确认页核对短码、设备名称
和平台。

Agent 以 JSON `{"device_code":"..."}` 轮询
`POST /api/v1/agent/device-authorizations/token`。服务端响应约定：

- `428 authorization_pending`：尚未确认；带 `Retry-After`。
- `429 slow_down`：轮询过快；必须按 `Retry-After` 等待。
- `429 rate_limited`：服务端全局或来源限流；Agent 保留 challenge 并按
  `Retry-After` 重试。
- `403 access_denied`：用户拒绝。
- `400 expired_token`：challenge 已过期。
- `400 invalid_device_code`：设备码无效或已经消费。
- `403 authorization_invalidated`：确认后账号角色、状态或认证版本发生变化。

成功只会发生一次，返回 `200` 和原有 `ppaass_session` HttpOnly Cookie。JSON 包含
`account`、`profile`（用户名、权限、密钥版本、有效期）、同一密钥版本的
`public_key_pem`/`private_key_pem`、`csrf_token`、`session_expires_at`，以及与原生
密码登录相同的 Agent access token。公钥专用于 Agent 在应用私钥前校验密钥对，不会
显示在普通用户确认页面。所有 API 响应统一带 `Cache-Control: no-store`。

challenge 的原始设备码和用户短码不会写入数据库；存储层只接收带不同域分隔的
SHA-256 摘要。状态更新和领取在 repository 内原子执行，并且服务端执行轮询限频、
短 TTL、一次消费和活动 challenge 数量上限。原生创建/轮询端点拒绝带 `Origin` 的
浏览器请求且没有 CORS 授权；浏览器 inspect/approve/deny 必须同时具有现有登录 Cookie
和 CSRF Token。

启用的普通用户或管理员都可以登录 Agent，但必须同时具有有效且未停用的 Proxy profile、
可解密的托管私钥以及 `key.private.read` 权限。没有 profile 的初始管理员不能绕过密钥
流程登录 Agent，须先在“我的账户”提交申请并由管理员批准。账号尚无密钥或密钥已过期时，
approve 返回现有的 `409 key_request_required`；challenge 保持 pending，账号仍需先提交
密钥申请并等待管理员设置有效期。

## 密钥申请、审批与有效期

本地注册只创建普通账号；首次启动创建的管理员也可以暂时没有 Proxy profile。没有
Proxy 配置或密钥已经过期时，普通用户和管理员都通过
`POST /api/v1/me/key-requests` 提交申请；同一账号同时只能有一条 `pending` 申请，
重复或并发提交会幂等返回同一条申请。管理员批准时必须给出严格晚于当前时间的
`expires_at`，RSA 密钥只在服务端生成，私钥加密入库且不会出现在管理员响应中。
用户可以附带一段可选的申请留言（去除首尾空白后最多 500 个字符）；留言随申请持久化，
用户等待审批时可以回看，管理员在待审批列表和审批对话框中可以看到。留言正文不会写入
tracing 日志。没有 JSON 请求体的旧客户端仍可提交无留言申请。申请被拒绝后，用户可以
重新提交。

`GET /api/v1/me` 的 `key_state` 为 `missing`、`active`、`expired` 或 `disabled`。
只有 `active` 状态才可由 Agent 领取连接凭据。账号直接轮换密钥需要同时满足：

- Web 账号处于启用状态；
- Proxy 用户配置已启用；
- 尚未到达 `expires_at`；
- 拥有 `key.rotate` 权限。

过期或缺失密钥不能通过用户或管理员的直接轮换接口恢复，也不能通过管理员 PATCH
清空有效期或把过期时间改到未来绕过审批；必须重新提交并批准密钥申请。管理员直接
创建用户仍属于已批准流程，`expires_at` 必填且必须严格晚于当前时间，额外权限会与
四项基础权限合并。数据库中保留的历史 legacy 用户不参与 Web 密钥申请流程。

Desktop Agent 登录后会在左侧账户区显示角色和权限。具有 `key.rotate` 权限且密钥仍有效
时，可以点击“生成新密钥”，输入当前登录密码后由 Agent 调用轮换接口、校验新密钥对并
直接写入本机配置；Agent 原本正在运行时会使用新凭据自动重启。缺失或过期密钥仍必须走
管理员审批，Agent 按钮不会绕过该规则。管理员还会看到进入完整用户管理页面的入口。

SQLite 模式下，已经建立的 TCP/Yamux relay 与原生 UDP 会话都会按 Proxy 的
`udp_session_authorization_recheck_secs` 周期重新检查账号启用状态、对应 TCP/UDP
权限、密钥版本和绝对过期时间，停用、撤权、提前过期或轮换密钥后最迟 5 秒关闭。
TCP 承载的共享 UDP relay 只在真正创建新 flow 前复核授权，Existing/AtCapacity
不增加查询，并使用不超过 1 秒的成功授权快照合并突发查询；原生 UDP 的
`OpenData` flow 保持同样的检查边界。

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
- `agent.packet_capture`
- `agent.config.view`
- `agent.egress.edit`
- `agent.runtime_threads.edit`

本地注册账号或管理员自身的密钥申请获批后，以及管理员直接创建 Web 普通用户时，Proxy
配置都会强制拥有前四项基础能力（TCP、UDP、领取和轮换密钥）。后四项是管理员可给
普通用户分配的 Agent 管理权限，默认不授予；管理员创建或编辑用户时可独立勾选，并会
保留数据库中的其他自定义权限。管理员后续通过 PATCH 更新权限时，不能移除基础能力。

Agent 管理员角色天然拥有全部四项 Agent 管理权限，不要求把它们重复写入管理员 profile。
普通用户的权限在界面和原生命令层同时执行：

- `agent.packet_capture` 控制抓包入口以及读取、启停和清空命令。
- `agent.config.view` 控制原始 TOML 配置的读取和编辑。
- `agent.egress.edit` 控制远端出口地址、连接超时、压缩格式和 UDP 会话数。
- `agent.runtime_threads.edit` 控制系统运行线程数。

管理员角色不绕过 Proxy 数据面的权限校验，其 TCP/UDP 流量仍使用该管理员自身 profile
中的基础连接权限。

Proxy 会在认证及 CONNECT/原生 UDP 边界实际执行 TCP/UDP 权限，不只是把权限展示在页面上。

## Proxy 与数据库边界

Proxy 只支持 SQLite 用户库：

```toml
users_database_path = "data/proxy-users.sqlite3"
access_log_database_path = "data/proxy-access.sqlite3"
access_log_database_group_writable = false
transport_identity_private_key_path = "data/proxy-identity-private.pem"
```

Proxy Web 是用户 schema 和账号写入的唯一所有者；Proxy 以 read-only/query-only
方式打开用户库。旧数据库里已有的 `origin=legacy` 记录继续保留，但服务不再提供
文件导入入口。legacy public-only 记录没有可登录领取的私钥，因此仍不能参与普通用户
密钥申请流程。

在 Unix 上，本地默认将两个 SQLite 的主文件及 sidecar 设为 `0600`。生产部署中，
Proxy Web 使用 `--database-group-readable` 将用户库设为 `0640`；Proxy 对它只读。
访问记录库通过 Proxy 的 `access_log_database_group_writable = true` 与 Proxy Web 的
`--access-log-database-group-writable` 显式设为 `0660`，并放在独立的 setgid 共享
目录。

两个业务层只依赖数据库无关 Repository。将来增加 PostgreSQL 等数据库时，应新增适配器并在启动阶段选择实现，无需修改 Proxy 认证或 Axum handler。
