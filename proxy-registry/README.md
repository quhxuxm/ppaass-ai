# Proxy Registry 用户中心

`proxy-registry` 是独立监听端口的账号与 Proxy 用户管理服务：

- Axum 提供注册、登录、用户自助和管理员 API。
- Vue 3 + PrimeVue 4 提供普通用户中心与管理员控制台。
- 本地密码使用 Argon2id 哈希；登录态使用服务端不透明会话、HttpOnly Cookie 和 CSRF Token。
- RSA 私钥使用部署主密钥 AES-256-GCM 加密后写入数据库，公钥与私钥按版本原子更新。
- `proxy-registry::store` 中的 `UserRepository`、`AccountRepository`、
  `ProxyAddressRepository`、`AccessLogRepository` 和
  `AgentDeviceAuthorizationRepository` 是数据库无关接口；
  当前适配器使用 SQLite。
- Registry 独占用户和访问记录 SQLite；Entry 通过受 Token 保护的 HTTP/SSE 控制面读取
  授权并批量上报访问记录，不再打开数据库。全部服务日志使用 `tracing`，不会记录密码、
  Cookie、控制 Token 或私钥。
- 多个 Proxy Registry 通过共享数据库中的事件日志同步 Agent SSE 通知。事件由业务事务
  使用普通 SQL 显式写入，不依赖数据库触发器；每个 Registry 实例独立轮询并只向连接
  在本实例上的 Agent 广播。

## 首次启动与管理员账号

系统不再使用“管理员 Token”。首次打开一个没有管理员的数据库时，通过环境变量创建真实管理员账号：

```bash
export PPAASS_PROXY_REGISTRY_BOOTSTRAP_ADMIN_PASSWORD="replace-with-a-strong-password"
export PPAASS_PROXY_REGISTRY_KEY_ENCRYPTION_SECRET="replace-with-at-least-32-random-bytes-and-keep-it-stable"
export PPAASS_PROXY_REGISTRY_CONTROL_TOKEN="replace-with-at-least-32-random-bytes"

RUST_LOG=proxy_registry=debug,tower_http=info \
  cargo run -p proxy-registry
```

根管理员用户名固定为 `admin`；如果仍设置
`PPAASS_PROXY_REGISTRY_BOOTSTRAP_ADMIN_USERNAME`，它也只能是 `admin`。其他管理员不能阻止
系统补建根管理员。`admin` 一旦存在，bootstrap 密码不会覆盖账号。不要把密码写进仓库
或命令行参数。

`PPAASS_PROXY_REGISTRY_KEY_ENCRYPTION_SECRET` 至少 32 字节，并且必须在服务重启和迁移后保持一致；丢失它将无法解密已托管的私钥。生产环境应从 Secret Manager 注入并单独备份。

## GitHub Actions 分离部署

Entry 和 Registry 使用两个独立的手动工作流，应用运行时不要求部署在同一服务器：

- `.github/workflows/deploy-proxy-registry.yml`：构建 Registry 和 Vue，部署两个 Registry
  进程，并让 Caddy 同时负载均衡公开 Web API 与内部控制 API。
- `.github/workflows/deploy-proxy-entry.yml`：只构建和部署 Entry，不安装 Caddy，也不
  接触 SQLite。

Registry 工作流绑定 `registry_production` GitHub Environment，并读取
`REGISTRY_PRODUCTION_REMOTE_HOST/USER/PASSWORD`；Entry 工作流绑定
`entry_production`，并读取 `ENTRY_PRODUCTION_REMOTE_HOST/USER/PASSWORD`。部署使用
密码方式的 SSH/SCP，并显式关闭客户端公钥认证；服务器主机指纹在该次工作流首次连接时
自动接受，不需要额外配置 known_hosts Secret。远端用户当前必须是能够管理 systemd、
系统用户和 Caddy 的 root 用户。
Registry 主机需预先安装 systemd、Caddy、OpenSSL 和 curl；Entry 主机需预先安装
systemd、OpenSSL 和 curl。

完整的 Secrets、Variables、Environment 示例、PEM 公私钥格式和安全录入方式见
[`docs/GITHUB_ACTIONS_DEPLOYMENT.md`](../docs/GITHUB_ACTIONS_DEPLOYMENT.md)。

Registry 的两个进程共享
`/var/lib/ppaass/users/proxy-users.sqlite3` 和
`/var/lib/ppaass/access/proxy-access.sqlite3`。公开端口为
`127.0.0.1:8787/8788`，控制端口为 `127.0.0.1:8797/8798`。Caddy 对公开 Web/API
使用 Cookie 粘性负载均衡，避免进程内 Web 会话跨实例丢失；无状态控制 API 使用随机
负载均衡。管理员界面的会话响应包含实际提供请求的
`registry_instance_id`，因此每次刷新都能看到当前连接到的实例。

控制面没有依赖 Redis、数据库触发器或进程内唯一消费者。授权变更由业务事务使用普通
SQL 写入事件表；每个 Registry 进程轮询同一中央存储并向本进程上的 SSE 连接广播。
Entry 注册成功或收到授权变更事件后读取完整的公钥授权快照，并在校验成功后原子替换
最后一次成功快照。首份完整快照到达前认证默认拒绝；此后 Registry 暂时不可用不会影响
快照中已有用户。中断期间发生的停用、删除、撤权或密钥轮换会在恢复连接并成功同步后
整体生效。访问记录使用 `entry_id + batch_id` 做普通 SQL 幂等写入。将来把 SQLite
替换为中央数据库时，Entry 和 Agent 的协议不需要变化。

首次从旧的同机部署拆分时：

1. 保留 Registry 主机上的 `/var/lib/ppaass/users`、`access` 和 `secrets`。
2. 将原 Registry 加密主密钥录入
   `REGISTRY_PRODUCTION_KEY_ENCRYPTION_SECRET`，并配置两边相同的控制 Token。
3. 部署 Registry，再部署 Entry。
4. 确认两个 Registry 本地健康端点、Caddy HTTPS 端点和 Entry systemd 服务均正常后，
   再下线旧的同机 Entry。

本地手动启动时，Registry 的公开监听与控制监听必须分开：

```bash
export PPAASS_PROXY_REGISTRY_CONTROL_TOKEN="replace-with-at-least-32-random-bytes"
cargo run -p proxy-registry -- \
  --listen 127.0.0.1:8787 \
  --control-listen 127.0.0.1:8797
```

生产环境保持 Axum 只监听回环地址，由 Caddy 提供 HTTPS。同一 Registry 公共 Host 上的
`/control/*` 控制接口也必须使用 TLS；如需进一步限制来源，可在 Caddy 中只允许 Entry
主机访问该路径。应用层仍会强制校验 Bearer Token。

## Vue 本地开发

前端开发服务器会把 `/api` 和 `/healthz` 转发给 Axum：

```bash
cd proxy-registry/frontend
npm install
npm run dev
```

浏览器打开 `http://127.0.0.1:5173`。如 Axum 使用其他地址，可通过
`PPAASS_PROXY_REGISTRY_API_TARGET` 修改 Vite 的代理目标。

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
| `GET` | `/api/v1/agent/me` | Agent 收到 SSE 事件后使用 Bearer 凭据刷新账号状态和权限 |
| `PUT` | `/api/v1/agent/proxy-entry` | 有自选权限的 Agent 用户修改本人使用的 Proxy Entry |
| `GET` | `/api/v1/agent/events` | Agent 使用 Bearer 凭据建立 SSE 实时通知流 |
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
| `GET/POST` | `/api/v1/admin/proxy-addresses` | 管理员查询或新增 Agent 可用的 Proxy 地址；查询包含已注册 Entry 的心跳状态 |
| `PATCH/DELETE` | `/api/v1/admin/proxy-addresses/{proxy_address_id}` | 管理员修改、停用或删除 Proxy 地址 |
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

Desktop、Windows 和 Android Agent 的登录页直接向配置文件中的 Proxy Registry 地址发送
`POST /api/v1/agent/login`，地址不会展示给用户。该原生端点拒绝带浏览器 `Origin` 的
请求，不创建 Web Cookie；认证成功后一次返回当前账号角色、Proxy profile 权限、管理员
分配的 Proxy 地址、同一版本的连接密钥，以及仅供 Agent 使用的
`agent_access_token`。

Agent access token 使用部署主密钥派生的独立 AES-256-GCM key 加密认证，服务重启后仍可
验证。Agent 把 token 与受管私钥一起保存到仅当前系统用户可读的本机凭据目录，绝不传给
前端脚本或写入日志。登录后 Agent 建立一条长期 SSE 连接：

```http
GET /api/v1/agent/events
Accept: text/event-stream
Authorization: Bearer <agent_access_token>
```

SSE 只发送 `sync`、`profile_changed`、`profiles_changed`、
`key_request_changed` 和 `admin_key_requests_changed` 等无敏感数据的事件。建立连接时
服务端立即发送一次 `sync`；权限、账号状态、Proxy 地址目录或密钥审批发生变化时，再
定向发送相应事件。Agent 收到事件后才调用：

```http
GET /api/v1/agent/me
Authorization: Bearer <agent_access_token>
```

响应返回最新角色、账号状态、`key_state`、权限和滚动更新的 token。Agent 不按固定
间隔轮询业务接口；SSE 使用 15 秒注释心跳维持连接，断线后按 1–60 秒指数退避重连。
服务端每 12 小时主动结束一次事件流，客户端重连并由新的 `sync` 事件刷新 token，避免
长期无业务事件时凭据过期。权限变更会直接刷新 Agent 界面和 Rust/原生命令层约束，
不要求退出或重启。临时网络错误、5xx、401 均不会清除登录、私钥或停止代理；Agent
保留最后一次成功验证的权限并显示同步错误。账号被停用或密钥过期时，接口仍返回 200
和权威状态，Agent 保留登录但显示明确错误。

密码登录、设备 token 领取和 `GET /api/v1/agent/me` 的成功响应都会在
`profile.proxy_addresses` 返回 1 到 32 个已启用的规范地址。该字段按地址稳定排序并
去重；Agent 只在原生后端使用，不在界面、日志或 `agent.toml` 中展示或持久化。
拥有 `agent.proxy_entry.select` 权限的账号还会收到管理员分配范围内 Entry 的图标键、名称、
描述、在线状态和当前多选集合，但地址仅供 Agent 运行层使用。用户通过
`PUT /api/v1/agent/proxy-entry` 提交 `{"proxy_entry_ids":["pxy_a","pxy_b"]}` 修改本人选择；
至少须选择一个，且任何未分配或已停用的 ID 都会被拒绝。没有该权限时服务端不返回 Entry 目录，
Agent 也不显示选择入口，并继续使用管理员分配的地址。撤销权限会立即恢复管理员分配，
不会继续应用用户此前的选择。
Android Agent 和桌面 Agent 会把当前 Entry 置顶，并在用户点击“确认切换”后
才提交多选集合。每个 Entry
可以独立测速：Agent 使用本人密钥直接认证该 Entry，由 Entry 在有界、加密的测试流中
下发随机数据，结果显示 Agent 到 Entry 的连接延迟和下载吞吐；测速不访问第三方目标，
也不会切换当前 Entry 或在界面暴露地址。
`GET /api/v1/me` 也返回同一字段，供原生 Agent 轮换密钥后继续使用；Web 用户中心故意
忽略它。已迁移账号尚未分配地址时，Agent 凭据端点返回 HTTP 409：

```json
{"error":{"code":"proxy_address_not_assigned","message":"..."}}
```

客户端收到该错误后应停止 Agent 网络运行并保留登录态，等待管理员完成地址分配。

## 设备授权 API（可选）

服务端仍提供一次性设备授权 API。需要该流程的原生客户端先向配置好的 Proxy Registry 地址
发送：

```http
POST /api/v1/agent/device-authorizations
Content-Type: application/json

{"platform":"android","client_name":"Alice Android"}
```

响应包含 256 位随机 `device_code`、12 字符短码、相对验证地址、600 秒有效期和 5 秒
建议轮询间隔：

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

Agent 使用自身配置的 Proxy Registry base URL 拼接 `verification_uri_complete`，并交给系统
浏览器打开。用户使用本地账号密码完成网页登录，然后在独立确认页核对短码、设备名称
和平台。

Agent 以 JSON `{"device_code":"..."}` 轮询
`POST /api/v1/agent/device-authorizations/token`。服务端响应约定：

- `428 authorization_pending`：尚未确认；带 `Retry-After`。
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

已经建立的 TCP/Yamux relay 与原生 UDP 会话都会按 Proxy 的
`udp_session_authorization_recheck_secs` 周期从本地最后一次成功快照重新检查账号启用
状态、对应 TCP/UDP 权限、密钥版本和绝对过期时间。Registry 可用时，停用、撤权、提前
过期或轮换密钥在新快照同步后最迟一个复核周期生效；控制面中断期间则延迟到恢复同步。
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
- `agent.egress.edit`
- `agent.runtime_threads.edit`
- `agent.proxy_entry.select`

本地注册账号或管理员自身的密钥申请获批后，以及管理员直接创建 Web 普通用户时，Proxy
配置都会强制拥有前四项基础能力（TCP、UDP、领取和轮换密钥）。后四项是管理员可给
普通用户分配的 Agent 管理权限，默认不授予；管理员创建或编辑用户时可独立勾选，并会
保留数据库中的其他自定义权限。管理员后续通过 PATCH 更新权限时，不能移除基础能力。

Agent 管理员角色天然拥有全部四项 Agent 管理权限，不要求把它们重复写入管理员 profile。
普通用户的权限在界面和原生命令层同时执行：

- `agent.packet_capture` 控制抓包页面以及读取、启停和清空命令；没有权限时整个抓包
  页面均不显示，转发中的明文抓包也统一放在抓包页面。
- `agent.egress.edit` 控制整个出口页面；没有权限时页面不显示，Agent 使用内置出口
  默认值，不使用本机持久化的出口配置。
- `agent.runtime_threads.edit` 控制系统运行参数面板；没有权限时面板不显示，Agent
  使用内置系统运行参数，不使用本机持久化的相关配置。
- `agent.proxy_entry.select` 控制 Proxy Entry 目录与本人选择接口；没有权限时目录和
  选择入口均不返回或显示，Agent 只使用管理员分配的 Proxy Entry。

数据库升级到 schema v7 时会移除已经停用的 `agent.config.view` 权限；查看配置不再是
管理员可分配的 Agent 权限。

管理员角色不绕过 Proxy 数据面的权限校验，其 TCP/UDP 流量仍使用该管理员自身 profile
中的基础连接权限。

Proxy 会在认证及 CONNECT/原生 UDP 边界实际执行 TCP/UDP 权限，不只是把权限展示在页面上。

## Proxy 地址目录与账号分配

schema v8 新增 `proxy_addresses` 地址目录和 `account_proxy_addresses` 账号分配关系。
迁移只创建空表并保留原账号、profile 和密钥，不会从开发配置或历史运行参数猜测、导入
任何生产地址。升级后管理员必须先在管理控制台建立地址目录，再为已有账号分配至少一个
已启用地址；完成前这些账号的 Agent 登录和同步会按上述稳定 409 错误失败。

目录项使用服务端生成且不会随地址修改而变化的不透明 ID。标签可省略或留空，此时响应和
控制台使用规范地址作为标签。地址只接受 `hostname:port`、`IPv4:port` 或
`[IPv6]:port`，拒绝 URL、路径和空白字符；主机名转为小写，端口转为无前导零的十进制
形式后再执行严格唯一约束。

管理员创建用户、编辑用户或批准密钥申请时，都必须通过 `proxy_address_ids` 选择
1 到 32 个不同的已启用目录项。重复 ID 会被拒绝，不会静默去重；账号变更、审批生成
密钥和地址关系替换在同一 repository 事务中提交。仍被账号引用的地址不能停用；目录项
可以直接删除，删除事务会先清除其全部账号分配再删除目录项。没有其他已分配节点的账号
随后进入未分配状态，Agent 登录或同步按稳定的 `proxy_address_not_assigned` 错误关闭代理。

管理员用户列表显示每个账号当前分配的目录项，Agent UI 则从不展示远端地址。业务层只
依赖 `ProxyAddressRepository` 和账号 repository；SQLite 表和 SQL 不进入 Axum handler，
后续增加其他数据库时可以用新适配器保持同一事务语义和 API 契约。

schema v13 在同一地址目录中增加可空的 Entry 注册字段。Entry 每 30 秒通过受 Bearer
Token 保护的 `/control/v1/entries/register` 上报稳定 ID、版本和 `advertised_address`。
首次注册会自动创建启用节点；若同地址人工节点已经存在，则原位绑定并保留标签、启用状态
和账号分配。最后心跳超过 90 秒时控制台显示离线；在线状态由查询时间推导，不使用触发器。

## Entry 与 Registry 数据边界

Entry 配置控制面和仅属于本节点的公开授权副本数据库：

```toml
entry_id = "entry-production"
advertised_address = "entry.example.com:443"
registry_url = "https://registry.example.com"
registry_control_token_path = "/var/lib/ppaass-entry/secrets/registry-control-token"
authorization_database_path = "/var/lib/ppaass-entry/authorization.sqlite3"
```

Proxy Registry 是用户、账号和访问记录权威 schema 的唯一所有者；Entry 不链接 Registry
存储 crate，也不打开 Registry 的数据库。Entry 自己的 SQLite 只保存 Registry 下发的公开
授权副本，不包含私钥、密码、会话或访问记录。旧数据库里已有的 `origin=legacy` 记录继续
保留，但服务不再提供文件导入入口。legacy public-only 记录没有可登录领取的私钥，因此
仍不能参与普通用户密钥申请流程。

Entry 在 TCP 和 UDP 都监听成功后才启动注册心跳与授权 SSE；构造和部署阶段都不探测
Registry。Registry 暂时不可用只会触发后台重试，不会阻止 Entry 数据面进程启动。
Entry 会在注册成功后获取完整授权快照，并在 SSE 通知变更时重新获取。同步使用按用户名
排序的 keyset cursor 分页，每页最多 256 条；第一页返回数据库 revision，后续页必须携带
同一个 revision。存在下一页时当前页固定填满 256 条，末页可以少于 256 条，因此十万用户
最多需要 391 页。翻页期间授权发生变化时 Registry 返回 `409 Conflict`，Entry 清理
暂存页并从第一页重试，不会提交混合版本。

Entry 每次只校验并写入一页本地 SQLite staging，所有页面完成后才在单个本地事务中原子
切换 active 副本；刷新失败不会清空已有快照。认证按用户名主键查询本地数据库，不把所有
公钥常驻内存。尚未取得首份快照时，Entry 保持运行但拒绝用户认证；已提交的最后成功快照
可跨 Registry 中断和 Entry 重启继续使用。
`GET /control/v1/authorizations/snapshot` 的每一页在同一个数据库只读事务中返回公开授权和
持久事件 revision；`GET /control/v1/events` 使用该 revision 驱动后续刷新。两个接口均
使用与 Entry 注册相同的 Bearer Token，不返回私钥或账号密码。
`registry_url` 可使用 HTTP 或 HTTPS；按当前部署要求，Entry 的 Registry HTTPS 客户端
不校验证书链和主机名。

在 Unix 上，本地默认将两个 SQLite 的主文件及 sidecar 设为 `0600`。生产部署中两个
Registry 进程使用同一无登录 UID，因此不再需要把数据库授权给 Entry。控制 Token 使用
`0600` 文件，并分别部署到两个服务主机。

Registry handler 只依赖数据库无关 Repository。将来增加 PostgreSQL 等中央数据库时，
应新增适配器并在启动阶段选择实现，无需修改 Entry 认证、控制协议或 Axum handler。
