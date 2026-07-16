# OpenAI-LB

OpenAI-LB 是一个面向 OpenAI / CodeX OAuth 渠道的反向代理和负载均衡器。它以单个 Rust 可执行文件交付，内嵌 React + shadcn 管理界面，并使用 SQLite 保存配置、权限、渠道、API Key、用量和逐调用审计。

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
- 创建 `~/.openai-lb/master.key`；Unix 权限固定为 `0600`。
- 提供 Setup API 和 Setup GUI。

打开 `http://localhost:8080`，填写品牌提供的 Auth Mini issuer，使用该 Auth Mini 实例登录，再将当前用户绑定为唯一 `root`。Setup 完成后初始化入口立即关闭。

OpenAI-LB 连接现有的品牌 Auth Mini 实例。用户不需要为 OpenAI-LB 部署 Auth Mini。前端使用 `auth-mini` SDK，后端通过 issuer 的 `/jwks` 验证 Ed25519 JWT，并使用 `user_id` 关联本地 `root / admin / user` 权限。

## 产品能力

- 注册多组 CodeX OAuth `access_key` / `refresh_key`，支持 PKCE OAuth 和自动刷新。
- 以 API Key 为租户调用凭据，密钥只显示一次，数据库只保存 SHA-256 哈希。
- 按 API Key 汇总请求、Token、缓存 Token、错误和延迟。
- 每次代理调用保留请求 ID、用户、API Key、渠道、接口、模型、状态、耗时和用量。
- 支持显式亲和键、会话头和 Responses 会话字段；亲和键在持久化前进行 SHA-256 哈希。
- 跟踪 `Retry-After` 与 `x-ratelimit-*`，对 429 渠道自动冷却并在到期后恢复。
- 对 401/403 渠道标记认证错误；手工禁用渠道不会自动恢复。
- Responses、SSE、音频上传和二进制响应保持流式传输。

权限边界：

| 角色 | 权限 |
| --- | --- |
| `root` | 系统配置、用户角色、渠道、全局审计与个人 API Key |
| `admin` | 渠道、全局审计与个人 API Key |
| `user` | 个人 API Key、个人用量与个人审计 |

## 调用示例

在管理界面创建 API Key 后调用代理：

```bash
curl http://localhost:8080/v1/responses \
  -H 'Authorization: Bearer sk-REPLACE_ME' \
  -H 'Content-Type: application/json' \
  -H 'x-lb-affinity-key: deployment-a' \
  -d '{"model":"gpt-5.4","input":"Explain this Rust error","stream":true}'
```

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
  -d '{"model":"gpt-image-1.5","prompt":"A precise exploded diagram","size":"1024x1024"}'
```

## 数据与并发模型

SQLite 为单实例数据层。连接池中的每条连接统一启用 WAL、foreign keys、5 秒 busy timeout 和 `synchronous=NORMAL`，连接池上限为 4。

代理热路径使用内存渠道快照和亲和映射。渠道 Rate Limit 观测、亲和持久化、过期清理和 cooldown 恢复由后台任务批量提交。逐调用审计进入容量为 4096 的有界队列，由单 writer 以最多 128 条的事务写入；客户端取消仍结算为 HTTP 499。

音频 multipart 不会整体读入内存。请求体从 Axum `Body` 直接流入 Reqwest；因为流式请求体无法安全重放，音频上传开始后不执行跨渠道重试。Responses 和图像使用独立的小型 JSON 请求限制。

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

## 验证

```bash
cd web && npm run check && cd ..
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features --locked
```

Pull Request 工作流还会运行 RustSec 依赖审计。

## 安全说明

- `master.key` 不进入 SQLite 或可执行文件。丢失该文件后，现有 OAuth 凭据无法解密。
- 入站 `Authorization`、Cookie、hop-by-hop headers 和代理专用亲和头不会转发到上游。
- 审计不保存 prompt、请求正文、API Key 或 OAuth 凭据。
- SQLite 文件和 `master.key` 应位于本机磁盘；不要让多个实例通过网络文件系统同时写入同一数据库。
- 生产部署应在 OpenAI-LB 前提供 TLS，并限制数据目录的系统账户访问权限。

## License

[MIT](./LICENSE)
