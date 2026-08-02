# OpenAI-LB

OpenAI-LB 是一个面向 OpenAI / CodeX OAuth 上游提供商的反向代理和负载均衡器。它以单个 Rust 可执行文件交付，内嵌 React + shadcn 管理界面，并使用 SQLite 保存配置、权限、上游提供商、Consumer、用量和逐调用审计。

项目只处理 OpenAI / CodeX 能力，包括 Responses、Compact、图像生成、音频转写和模型列表。它不提供其他 AI 厂商的协议兼容层。

## 直接运行

从 [GitHub Releases](https://github.com/zccz14/OpenAI-LB/releases) 下载当前平台的压缩包并校验同名 `.sha256` 文件，然后运行：

预构建发布覆盖 Linux x86_64、Linux arm64 和 Apple Silicon macOS。Windows 与 Intel macOS 不进入官方 Release 构建矩阵。

```bash
./openai-lb
```

服务监听 `0.0.0.0:8080`。首次启动会自动完成以下本地准备：

- 创建 `~/.openai-lb/`。
- 创建 `~/.openai-lb/openai-lb.sqlite3` 并执行版本化迁移。
- 提供 Setup API 和 Setup GUI。

打开 `http://localhost:8080`，填写品牌提供的 Auth Mini issuer，然后前往该 Auth Mini 实例的托管登录页面。登录成功后浏览器会返回 OpenAI-LB，再将当前用户绑定为唯一 `root`。Setup 完成后初始化入口立即关闭。

OpenAI-LB 连接现有的品牌 Auth Mini 实例。用户不需要为 OpenAI-LB 部署 Auth Mini。前端使用 `auth-mini` SDK，后端通过 issuer 的 `/jwks` 验证 Ed25519 JWT，并使用 `user_id` 关联本地 `root / admin / user` 权限。

## 产品能力

- 注册多组 CodeX OAuth `access_key` / `refresh_key`，支持 PKCE OAuth 和自动刷新。
- 每个上游 Provider 记录 `owner_id`；普通用户可管理自己的 Provider，并按完整 `user_id` 授权其他用户使用。
- 以 Consumer 为租户调用凭据，密钥只显示一次，数据库只保存 SHA-256 哈希。
- 按 Consumer 汇总请求、Token、缓存 Token、错误和延迟。
- root 与管理员可在总览查看宿主机 CPU、内存、网络、磁盘和 SQLite 文件占用。
- 每次代理调用保留 Thread ID、请求 ID、用户、Consumer、上游提供商、接口、模型、状态、耗时和用量；请求/响应诊断记录仅对开启 `request_archive` 的 Consumer 保存，失败和客户端取消同样遵循该开关。
- 支持显式亲和键、会话头和 Responses 会话字段；亲和键在持久化前进行 SHA-256 哈希。
- 跟踪 `Retry-After` 与 `x-ratelimit-*`，对 429 上游提供商自动冷却并在到期后恢复。
- 对 401/403 上游提供商标记认证错误；手工禁用上游提供商不会自动恢复。
- Responses、SSE、音频上传和二进制响应保持流式传输。

权限边界：

| 角色 | 权限 |
| --- | --- |
| `root` | 系统配置、用户角色、全部 Provider、全局审计与个人 Consumer；可使用全部 Provider |
| `admin` | 全部 Provider、全局审计与个人 Consumer；可使用全部 Provider |
| `user` | 自有 Provider 及其用户授权、个人 Consumer、个人用量与个人审计；可使用自有、获授权或由 `provider_access` 全局权限覆盖的 Provider |

## 调用示例

在管理界面为每个 AI App 创建一个独立 Consumer 后调用代理。这样可以按 App 隔离用量、错误记录和吊销范围：

```bash
curl http://localhost:8080/v1/responses \
  -H 'Authorization: Bearer sk-REPLACE_ME' \
  -H 'Content-Type: application/json' \
  -H 'x-lb-affinity-key: deployment-a' \
  -d '{"model":"gpt-5.4","input":"Explain this Rust error","stream":true}'
```

Thread ID 是逐调用审计从下游请求中提取的线程标识。CodeX 请求使用 `x-codex-conversation-id`，其他 App 可使用其已有的 `thread-id`；请求未携带这两个头时，审计记录中的 Thread ID 为空。Thread ID 属于基础审计字段，无论 Consumer 是否开启 `request_archive` 都会落库；代理不会向响应添加额外字段或请求头。

```bash
curl http://localhost:8080/v1/audio/transcriptions \
  -H 'Authorization: Bearer sk-REPLACE_ME' \
  -F 'file=@meeting.wav' \
  -F 'model=gpt-4o-transcribe'
```

```bash
curl http://localhost:8080/v1/images/generations \
  -H 'Authorization: Bearer sk-REPLACE_ME' \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-image-2","prompt":"A precise exploded diagram","size":"2048x1152"}'
```

`gpt-image-2` accepts custom `WIDTHxHEIGHT` image sizes. Both dimensions must be multiples of 16 and no larger than 3840; the aspect ratio cannot exceed 3:1, and the total pixel count must be 655,360–8,294,400. Set `size` to `auto` to let the upstream choose.

## 数据与并发模型

SQLite 为单实例数据层。连接池中的每条连接统一启用 WAL、foreign keys、5 秒 busy timeout 和 `synchronous=NORMAL`，连接池上限为 4。

代理热路径使用内存上游提供商与授权快照和亲和映射。每次选择先按调用用户过滤：具备全局权限时使用完整 Provider 池，否则只使用自有或已获授权的 Provider；随后在该集合内执行可用性、亲和和负载选择。撤销授权后重新加载快照，新请求立即停止使用对应 Provider。上游提供商 Rate Limit 观测、亲和持久化、过期清理和 cooldown 恢复由后台任务批量提交。逐调用审计与请求/响应诊断记录进入容量为 4096 的有界队列，由单 writer 以最多 128 条的事务写入；审计队列不会阻塞代理，SQLite 暂时不可写时已入队事件会退避重试，队列耗尽时会丢弃新审计并限频记录。客户端取消仍结算为 HTTP 499。Consumer 的 `request_archive` 开关默认关闭，开启后才保存最多 1 MiB 的请求/响应正文预览并标记是否截断；诊断归档另有 64 MiB 内存预算，耗尽时只跳过正文诊断，基础 `api_calls` 审计仍会写入。认证、Cookie、Token、Secret 和 Consumer 凭据类请求头不会写入。诊断记录默认保留 24 小时，可由 root 在“设置”中配置为 1–365 天；后台每小时自动清理过期诊断记录，长期用量审计不受影响。

音频 multipart 不会整体读入内存。请求体从 Axum `Body` 直接流入 Reqwest；因为流式请求体无法安全重放，音频上传开始后不执行跨上游提供商重试。Responses 和图像使用独立的小型 JSON 请求限制。

## 本地开发

要求 Rust 1.93、Node.js 24 和 npm。

```bash
cd web
npm ci
npm run build
cd ..
cargo run
```

开发前端时运行 `npm run dev`；Vite 会把 API 请求代理到 `http://localhost:8080`。

生产构建先生成一次 `web/dist`，Rust 只负责嵌入已有静态资源：

```bash
cd web && npm ci && npm run check && cd ..
cargo build --release --locked
```

`build.rs` 不启动 npm，因此 Rust 构建环境不需要 Node。GitHub Release 工作流先构建一次前端，再复用相同产物生成各平台二进制。

## 生产部署

生产环境运行在 AWS Singapore 的 `openai-lb` EC2，并通过 <https://openai.ntnl.io> 提供 HTTPS 服务。Nginx 只负责 TLS 和流式反向代理；SQLite 与应用配置保存在实例的 `/var/lib/openai-lb/.openai-lb/`。

推送 `v*` tag 后，Release workflow 会先发布三个官方平台资产，再使用 GitHub OIDC 和 AWS Systems Manager 将 Linux x86_64 资产部署到 EC2。部署过程校验 Release 的 SHA-256，使用 systemd 重启服务并执行本机健康检查；健康检查失败时恢复上一版本。仓库不保存 AWS 长期密钥，也不开放 SSH 入站端口。

部署 Action 使用以下 Repository variables：

- `AWS_DEPLOY_ROLE_ARN`
- `AWS_REGION`
- `EC2_INSTANCE_ID`

## 验证

```bash
cd web && npm run check && cd ..
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features --locked
```

Pull Request 工作流还会运行 RustSec 依赖审计。

## 安全说明

- OAuth PKCE verifier 只保存在单实例进程内，十分钟后过期；服务重启会使未完成的 OAuth 授权失效。
- 升级前版本遗留的 `master.key` 已不再使用，可在新版本部署后删除。
- 入站 `Authorization`、Cookie、hop-by-hop headers 和代理专用亲和头不会转发到上游。
- 请求/响应诊断记录会保存最多 1 MiB 的正文预览以便排查；SQLite 文件因此可能包含 prompt、输出或音频片段，应按敏感业务数据保护并使用较短保留期。
- 诊断记录不会保存 Authorization、Cookie、Token、Secret、Consumer 类请求头或 OAuth 凭据。
- SQLite 文件应位于本机磁盘；不要让多个实例通过网络文件系统同时写入同一数据库。
- 生产部署应在 OpenAI-LB 前提供 TLS，并限制数据目录的系统账户访问权限。

## License

[MIT](./LICENSE)
