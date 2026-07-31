# GitHub Actions 部署配置

本文档说明以下两个手动部署工作流所需的 GitHub Actions Secrets 和 Variables：

- `.github/workflows/deploy-proxy-registry.yml`
- `.github/workflows/deploy-proxy-entry.yml`

UT 由独立的 `.github/workflows/unit-test.yml` 执行，支持 push、pull request 和手动
触发。两个部署工作流只执行源码静态约束、发布构建和安装脚本语法检查，不再重复运行
Rust、前端 UT 或部署契约测试。

当前工作流使用两个独立的 GitHub Environment，因此 Registry 和 Entry 可以部署到
不同服务器：

| 工作流 | `inputs.environment` | Secrets/Variables 前缀 |
| --- | --- | --- |
| Registry | `registry_production` | `REGISTRY_PRODUCTION_*` |
| Entry | `entry_production` | `ENTRY_PRODUCTION_*` |

工作流通过以下表达式动态读取远程部署凭据：

- `secrets[format('{0}_REMOTE_HOST', inputs.environment)]`
- `secrets[format('{0}_REMOTE_USER', inputs.environment)]`
- `secrets[format('{0}_REMOTE_PASSWORD', inputs.environment)]`

GitHub Secret 和配置 Variable 名称引用均不区分大小写，但建议统一使用本文档中的
大写名称。
其他配置使用相同规则，例如 `registry_production` 的控制 Token 为
`REGISTRY_PRODUCTION_CONTROL_TOKEN`，`entry_production` 的控制 Token 为
`ENTRY_PRODUCTION_CONTROL_TOKEN`。

## 配置位置

可以在仓库的 `Settings > Secrets and variables > Actions` 中配置 Repository 级别的
Secrets/Variables，也可以分别在 `registry_production` 和 `entry_production`
GitHub Environment 中配置。

无论放在 Repository 还是 Environment 层级，Entry 和 Registry 都使用不同名称，不会
互相覆盖。下文标记为“两边相同”的配置仍需分别录入，并保证两个值的内容完全一致。

## Registry production 配置

GitHub Environment：`registry_production`

### 必须的 Secrets

| Secret | 示例 | 约束与用途 |
| --- | --- | --- |
| `REGISTRY_PRODUCTION_REMOTE_HOST` | `203.0.113.10` | Registry 部署服务器 IP 或 DNS 名称，不带协议、端口或路径 |
| `REGISTRY_PRODUCTION_REMOTE_USER` | `root` | 当前必须是 UID 0 的 `root`；远端安装命令不会调用 `sudo` |
| `REGISTRY_PRODUCTION_REMOTE_PASSWORD` | `<部署服务器的强密码>` | SSH 密码，不能包含换行 |
| `REGISTRY_PRODUCTION_WEB_ADMIN_PASSWORD` | `<至少 8 位的管理员密码>` | 首次创建根管理员时使用；当前工作流每次部署都要求提供，但不会覆盖已有管理员密码 |
| `REGISTRY_PRODUCTION_KEY_ENCRYPTION_SECRET` | `<至少 32 位的随机主密钥>` | 加密 Registry 托管的用户私钥和 Token；升级、重启和数据库迁移时必须保持不变 |
| `REGISTRY_PRODUCTION_CONTROL_TOKEN` | `<至少 32 位的随机 Token>` | Entry 调用 Registry HTTP/HTTPS 控制 API 的 Bearer Token，不能包含空白；内容必须与 Entry 对应 Secret 相同 |

### 必须的 Variables

| Variable | 示例 | 约束与用途 |
| --- | --- | --- |
| `REGISTRY_PRODUCTION_REGISTRY_HOST` | `registry.example.com` | Registry 管理页面、公开 API 和 `/control/*` 控制 API 共用的地址，不带 `https://`、端口或路径 |

### 可选的 Variable

| Variable | 默认值 | 约束 |
| --- | --- | --- |
| `REGISTRY_PRODUCTION_RUNTIME_ROOT` | `/opt/ppaass-registry` | 只能使用 `/opt` 或 `/srv` 下的目录 |

## Entry production 配置

GitHub Environment：`entry_production`

### 必须的 Secrets

| Secret | 示例 | 约束与用途 |
| --- | --- | --- |
| `ENTRY_PRODUCTION_REMOTE_HOST` | `203.0.113.20` | Entry 部署服务器 IP 或 DNS 名称，不带协议、端口或路径 |
| `ENTRY_PRODUCTION_REMOTE_USER` | `root` | 当前必须是 UID 0 的 `root`；远端安装命令不会调用 `sudo` |
| `ENTRY_PRODUCTION_REMOTE_PASSWORD` | `<部署服务器的强密码>` | SSH 密码，不能包含换行 |
| `ENTRY_PRODUCTION_CONTROL_TOKEN` | `<与 Registry 完全相同的 Token>` | Entry 调用 Registry HTTP/HTTPS 控制 API 的 Bearer Token |

### 必须的 Variables

| Variable | 示例 | 约束与用途 |
| --- | --- | --- |
| `ENTRY_PRODUCTION_ID` | `entry-production-01` | Entry 的稳定唯一标识；不同 Entry 不能重复 |
| `ENTRY_PRODUCTION_ADVERTISED_ADDRESS` | `entry.example.com:443` | Agent 应连接的公网 `host:port`；Entry 会把它注册并合并到 Proxy 地址目录 |
| `ENTRY_PRODUCTION_REGISTRY_URL` | `https://registry.example.com:443` | Registry 的完整 HTTP/HTTPS 基础 URL，不得包含认证信息、路径、查询参数或 fragment |

### 可选的 Variable

| Variable | 默认值 | 约束 |
| --- | --- | --- |
| `ENTRY_PRODUCTION_RUNTIME_ROOT` | `/opt/ppaass-entry` | 只能使用 `/opt` 或 `/srv` 下的目录 |

## 同机并行部署与稳定主密钥

Entry 和 Registry 可以配置相同的远程服务器地址，同时启动两个独立工作流。Entry
安装脚本不连接或等待 Registry；Entry 成功监听 TCP/UDP 后，由后台 Tokio 任务立即注册，
失败时独立重试，不影响数据面进程启动。Registry 安装脚本仍会验证自身公开 API 和控制
API 的外部地址。

Registry 只使用 `REGISTRY_PRODUCTION_REGISTRY_HOST`。Caddy 在同一个站点中将
`/control` 和 `/control/*` 请求转发到 Control 监听端口，其余请求转发到 Registry
Web/API 监听端口。`ENTRY_PRODUCTION_REGISTRY_URL` 需要把协议和可选端口一并写入：
HTTPS 可填 `https://registry.example.com:443`，明文 HTTP 可填
`http://registry.example.com:80`。其中主机名应与
`REGISTRY_PRODUCTION_REGISTRY_HOST` 指向同一个 Registry。

Registry 部署脚本通过外部 Caddy 地址确认公开 API 和 Control API 均返回 HTTP 200。
考虑到部署目标可能使用自签名证书，这两个外部 HTTPS 自检不校验证书链或主机名；
本地两个 Registry 实例的 HTTP 健康检查不受影响。

从旧配置升级时，应新增 `ENTRY_PRODUCTION_REGISTRY_URL` 并填写上述完整 URL，然后
删除旧的 `ENTRY_PRODUCTION_REGISTRY_HOST` 和 `ENTRY_PRODUCTION_REGISTRY_SCHEME`；
新工作流不再读取旧变量或自动补全协议。

`REGISTRY_PRODUCTION_KEY_ENCRYPTION_SECRET` 与服务器已有
`/var/lib/ppaass/secrets/proxy-registry-key-encryption-secret` 不一致时，Registry 会
拒绝部署，绝不能自动覆盖。已有数据库必须继续使用首次部署时的原主密钥，否则已经加密
保存的用户私钥和 Token 将无法解密。迁移或重新配置 GitHub Environment 时，应先把原
主密钥安全录入 `registry_production`，再部署 Registry；确认 Registry 成功后再检查
Entry。

如果本机已登录 GitHub CLI，可以通过 SSH 将服务器原主密钥直接写入 GitHub Secret，
整个过程不会把密钥正文打印到终端：

```powershell
ssh root@registry-host "cat /var/lib/ppaass/secrets/proxy-registry-key-encryption-secret" |
  gh secret set REGISTRY_PRODUCTION_KEY_ENCRYPTION_SECRET --env registry_production
```

执行前将 `registry-host` 替换为实际 Registry 服务器地址。不要单独运行远端 `cat`
命令，也不要把主密钥复制到聊天、日志或文档中。

## 当前不再需要的配置

以下配置不再被当前工作流读取，可以从 GitHub 中删除：

- `PPAASS_DEPLOY_SSH_KNOWN_HOSTS`
- `PPAASS_WEB_ADMIN_PASSWORD`
- `PPAASS_PROXY_REGISTRY_KEY_ENCRYPTION_SECRET`
- `PPAASS_PROXY_CONTROL_TOKEN`
- `PPAASS_WEB_PUBLIC_HOST`
- `PPAASS_REGISTRY_CONTROL_PUBLIC_HOST`
- `REGISTRY_PRODUCTION_WEB_PUBLIC_HOST`
- `REGISTRY_PRODUCTION_CONTROL_PUBLIC_HOST`
- `ENTRY_PRODUCTION_CONTROL_PUBLIC_HOST`
- `ENTRY_PRODUCTION_REGISTRY_HOST`
- `ENTRY_PRODUCTION_REGISTRY_SCHEME`
- `PPAASS_PROXY_ENTRY_ID`
- `PPAASS_REGISTRY_RUNTIME_ROOT`
- `PPAASS_ENTRY_RUNTIME_ROOT`
- `PRODUCTION_REMOTE_HOST/USER/PASSWORD`
- `PRODUCTION_REGISTRY_REMOTE_HOST/USER/PASSWORD`
- `PRODUCTION_ENTRY_REMOTE_HOST/USER/PASSWORD`
- 对应的 `DEV_*` 和 `QA_*` 旧部署凭据

当前部署仍然通过 SSH/SCP 传输和安装发布包，但使用密码认证，并显式关闭客户端公钥
认证。服务器主机指纹在本次 Runner 首次连接时自动接受，不需要预先配置 known_hosts
Secret。
