# OpenAI-LB

OpenAI-LB 是面向 CodeX OAuth 的多租户反向代理与负载均衡器。它只实现 OpenAI / CodeX 能力，不提供 Claude、Gemini 等其他厂商协议兼容。服务以 Rust、Axum、Tokio 和 SQLite 构建，React + shadcn/ui 控制台会嵌入同一个 release binary。

## 能力边界

- 管理员可直接导入多组 `access_key` / `refresh_key`，或通过 PKCE OAuth 注册渠道；服务从 access JWT 解析 `chatgpt_account_id` 并在到期前刷新凭据。
- Auth Mini 提供浏览器登录和刷新；Rust 根据 issuer 与 `/jwks` 在本地验证 EdDSA access JWT。配置 `ADMIN_USER_ID` 时仅该用户成为管理员；未配置时，首位用户通过 SQLite 原子事务成为管理员。
- 租户 API Key 使用 `sk-` 前缀，只在创建响应中返回一次；SQLite 只保存 SHA-256 哈希。
- 支持 `/v1/responses`、`/v1/responses/compact`、对应的 `/backend-api/codex/...` 路径、`/v1/audio/transcriptions`、`/v1/images/generations` 和 `/v1/models`。
- Responses 和 SSE 响应按字节转发；音频 multipart 原样发往 CodeX `/transcribe`；图像请求转换为 Responses `image_generation` 工具并还原为 OpenAI Images envelope。
- API Key 验证成功后立即创建 pending 调用记录，并在无渠道、刷新/网络失败、上游响应、SSE 完成或客户端取消时结算；记录 request ID、租户、API Key、渠道、真实 HTTP method、路径、模型、状态、延迟、IP、错误及 Token，不记录 prompt、Authorization 或 OAuth 凭据。渠道与 OAuth 管理操作另写管理员审计。

当前未实现 `/v1/chat/completions`、其他厂商兼容接口、图像 edits 或实时 WebSocket。调用方应使用 OpenAI Responses API。

## 架构

```text
浏览器 ── Auth Mini SDK ── Auth Mini
   │ access JWT                │ /jwks
   └──────────┬────────────────┘
              ▼
       Axum 管理 API ── SQLite（用户、Key、渠道、亲和、审计）
              │
客户端 ─ sk- API Key ─► 代理入口 ─► 亲和 / least-inflight 调度
                                      │
                                      ├─ Responses / compact
                                      ├─ /transcribe
                                      └─ image_generation 转换
                                              │
                                              ▼
                                     CodeX OAuth 渠道池
```

调度先检查 `x-lb-affinity-key`，再检查 `session_id` / `x-session-id`，最后检查请求中的 `session_id`、`previous_response_id` 或 `prompt_cache_key`。映射以 SHA-256 键持久化并带 TTL。无有效亲和时，在可用渠道中选择 inflight 最少者，同压渠道使用轮询打破平局。

上游 `429` 会读取 `Retry-After` 或 `x-ratelimit-reset*`，将渠道置为 cooldown；到期后查询路径自动恢复。`401/403` 标记为 `auth_error`，需要管理员刷新凭据。手工禁用不会自动恢复。上游在响应尚未下发前返回 `401/403/429/5xx` 时，最多更换一次渠道；开始向客户端传输后不重试。

## 配置

复制 [`.env.example`](./.env.example) 并设置以下必填值：

| 变量 | 说明 |
| --- | --- |
| `ENCRYPTION_KEY` | 32 字节 base64，使用 `openssl rand -base64 32` 生成；AES-256-GCM 加密 OAuth 凭据 |
| `AUTH_MINI_ISSUER` | Auth Mini 对外 issuer，必须与其 `--issuer` 完全一致 |
| `DATABASE_URL` | 默认 `sqlite://openai-lb.sqlite?mode=rwc` |
| `ADMIN_USER_ID` | 设置后仅匹配用户是管理员；留空时首位用户成为管理员 |
| `CORS_ALLOWED_ORIGINS` | 逗号分隔的控制台来源，不要在生产环境使用通配符 |
| `CODEX_UPSTREAM_BASE` | 可替换为测试服务器；默认 `https://chatgpt.com/backend-api/codex` |

OAuth redirect URI 默认采用 CodeX CLI 的 `http://localhost:1455/auth/callback`。管理员完成浏览器授权后，可从回调地址复制 `code` 到控制台。生产环境若使用自有回调接收器，应同步设置 `CODEX_OAUTH_REDIRECT_URI`。

## 部署 Auth Mini

在 Auth Mini 项目或已安装的 CLI 中创建实例并允许控制台来源：

```bash
npx auth-mini create ./auth-mini.sqlite
npx auth-mini origin add ./auth-mini.sqlite --value https://lb.example.com
npx auth-mini start ./auth-mini.sqlite --issuer https://auth.example.com
```

将 `AUTH_MINI_ISSUER=https://auth.example.com` 配置到 OpenAI-LB。浏览器直接使用 `auth-mini/sdk/browser` 完成邮箱 OTP、Passkey、跨标签页会话恢复和 refresh token 轮换。refresh token 只在浏览器与 Auth Mini 之间流动，不发送给 OpenAI-LB。

## 本地开发

要求 Rust 1.93+、Node.js 24+ 和 npm。

```bash
cp .env.example .env
# 填写 ENCRYPTION_KEY 与 AUTH_MINI_ISSUER，然后加载环境变量
set -a; source .env; set +a

cd web
npm ci
npm run dev
```

另开终端启动后端。开发时 Vite 请求可通过 `web/vite.config.ts` 配置的代理访问 `8080`；也可以先执行 `npm run build`，直接从 Rust 服务访问内嵌页面。

```bash
cargo run
```

## 构建与运行单一 Binary

`build.rs` 会在 Cargo 构建时运行前端生产构建。首次构建先安装锁定的 npm 依赖：

```bash
cd web && npm ci && cd ..
cargo build --release --locked
./target/release/openai-lb
```

最终部署只需要 `target/release/openai-lb`、环境变量和 SQLite 文件所在的可写目录。也可使用容器：

```bash
docker build -t openai-lb .
docker run --rm -p 8080:8080 -v "$PWD/data:/data" --env-file .env openai-lb
```

SQLite 已启用 WAL、foreign keys 和 busy timeout。备份时同时处理 `.sqlite`、`.sqlite-wal` 与 `.sqlite-shm`，或在停写后执行 SQLite online backup。不要只复制正在写入的主文件。

## API 示例

创建 Key 必须在控制台登录后完成；以下 `sk-...` 是租户调用凭据。

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
  -d '{"model":"gpt-image-1.5","prompt":"A precise exploded diagram of a mechanical keyboard","size":"1024x1024"}'
```

## 验证

```bash
cd web && npm run check && cd ..
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release --locked
```

## 安全边界

- `ENCRYPTION_KEY` 不进入数据库或 binary；丢失后现有 OAuth 凭据无法恢复。当前版本不提供在线密钥轮换，轮换前应重新导入渠道。
- 入站 `Authorization` 和 hop-by-hop headers 不会发送给上游；上游只收到所选渠道的 OAuth access token。
- 审计错误会保留上游错误消息，但不会保存请求正文。仍应限制日志与 SQLite 的读取权限。
- SQLite 适合单实例部署。不要让多个主机通过网络文件系统同时写同一个数据库；横向扩展前需要迁移到具备分布式并发语义的数据层。
- API Key 是高熵 bearer secret。SHA-256 哈希用于数据库泄漏隔离，不替代客户端密钥保护、TLS、最小权限与定期吊销。
