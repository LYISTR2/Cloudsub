# CloudSub

> 部署在 Cloudflare Workers 上的订阅节点管理与分发系统。

## 功能概览

- **一键部署** — 从 GitHub 部署到自己的 Cloudflare 账户
- **多源导入** — 支持订阅 URL、手动粘贴配置文件，加密存储敏感数据
- **智能解析** — 自动识别 Base64、Clash YAML、URI 列表、内部 JSON 格式
- **节点处理** — 解析、去重（指纹）、分组、过滤、正则重命名、排序
- **多格式输出** — Mihomo (Clash Meta) / Sing-box / Raw Base64 / JSON
- **订阅令牌** — 带访问令牌的订阅地址，支持过期时间和令牌轮换
- **定时刷新** — Cron 定时拉取上游订阅，自动更新缓存
- **管理后台** — 轻量 SPA 管理界面，支持数据源、节点、订阅、审计日志管理
- **安全防护** — SSRF 防护、AES-GCM 加密、PBKDF2 密码哈希、CSRF 保护、登录限流

## 支持的协议

| 协议 | URI 解析 | Clash YAML 解析 | Sing-box 输出 |
|------|---------|----------------|--------------|
| Shadowsocks (ss) | ✅ | ✅ | ✅ |
| VMess | ✅ | ✅ | ✅ |
| VLESS | ✅ | ✅ | ✅ |
| Trojan | ✅ | ✅ | ✅ |
| Hysteria2 | ✅ | ✅ | ✅ |
| TUIC | ✅ | ✅ | ✅ |

## 支持的输出格式

| 格式 | target 参数 | 说明 |
|------|-----------|------|
| **Mihomo / Clash Meta** | `mihomo` | 完整 YAML 配置，含 proxy-groups（自动选择 / 手动选择）和分流规则（AI / Telegram / 流媒体 / Apple / 国内直连） |
| **Sing-box** | `singbox` | 完整 JSON 配置，含 outbounds（selector / urltest / direct / dns）、DNS 分流、路由规则 |
| **Raw Base64** | `raw` | 标准 Base64 编码的 URI 列表，保留全部传输参数（ws path / host / flow / alpn / obfs 等） |
| **JSON** | `json` | 内部 NormalizedNode JSON，供 API 对接使用 |

## 快速部署

### 前置条件

- Cloudflare 账户
- Node.js 22+
- npm

### 步骤

1. **Fork / Clone 本仓库**

2. **安装依赖**
   ```bash
   npm ci
   ```

3. **配置 Secrets**
   ```bash
   cp .dev.vars.example .dev.vars
   ```
   编辑 `.dev.vars`，填入：
   ```
   APP_SECRET=<随机32字节密钥>
   DATA_ENCRYPTION_KEY=<随机32字节密钥>
   ```
   生成密钥：`openssl rand -base64 32`

4. **创建 Cloudflare 资源**
   ```bash
   npx wrangler d1 create cloudsub
   npx wrangler kv namespace create CACHE
   ```
   将返回的 ID 填入 `wrangler.jsonc`。

5. **运行数据库迁移**
   ```bash
   npx wrangler d1 migrations apply cloudsub
   ```

6. **部署**
   ```bash
   npm run deploy
   ```

7. **初始化管理员**
   访问部署后的 URL，首次进入会提示创建管理员账户。

### GitHub Actions 自动部署

在仓库 Settings → Secrets 中配置：
- `CLOUDFLARE_API_TOKEN`
- `CLOUDFLARE_ACCOUNT_ID`

然后在 Actions 页面手动触发 `Deploy to Cloudflare` workflow。

## 订阅地址格式

```
https://<your-worker>.workers.dev/sub/<token>?target=mihomo
```

| 参数 | 说明 |
|------|------|
| `token` | 订阅访问令牌（创建订阅时生成） |
| `target` | 可选，`mihomo` / `singbox` / `raw` / `json`，默认使用订阅配置的 `defaultTarget` |

## 技术栈

| 组件 | 技术 |
|------|------|
| 运行时 | Cloudflare Workers |
| 数据库 | Cloudflare D1 (SQLite) |
| 缓存 | Cloudflare KV |
| 后端框架 | Hono |
| 前端 | React + Vite |
| ORM / 迁移 | Drizzle ORM |
| 校验 | Zod |
| 加密 | Web Crypto API (AES-GCM, PBKDF2, HMAC-SHA256) |

## 安全特性

- **SSRF 防护** — 拦截私有 IP (10.x / 127.x / 169.254.x / 172.16-31.x / 192.168.x)、链路本地、保留地址；强制 HTTPS；重定向重新校验
- **数据加密** — 数据源的 URL、请求头、内容使用 AES-256-GCM 加密存储
- **密码哈希** — PBKDF2-SHA256，210,000 次迭代
- **会话管理** — HMAC 存储的 session token，HttpOnly + Secure + SameSite=Strict cookie
- **CSRF 保护** — 双重 token（cookie + header），常量时间比较
- **登录限流** — 5 次失败后锁定 15 分钟
- **订阅限流** — 每 IP 每分钟 120 次请求
- **审计日志** — 所有管理操作记录到 audit_logs

## 项目结构

```
src/
├── shared/
│   └── types.ts              # 共享类型定义
├── worker/
│   ├── index.ts              # Worker 入口 (fetch + scheduled)
│   ├── app.ts                # Hono 路由 (37KB, 全部 API)
│   ├── env.ts                # 环境变量绑定
│   ├── adapters/
│   │   ├── input/            # 输入解析器
│   │   │   ├── index.ts      #   格式自动探测
│   │   │   ├── uri-list.parser.ts  # ss/vmess/vless/trojan/hy2/tuic URI
│   │   │   ├── clash.parser.ts     # Clash YAML
│   │   │   ├── internal-json.parser.ts
│   │   │   └── shared.ts     #   base64 / fingerprint / port
│   │   └── output/
│   │       └── index.ts      # Mihomo / Sing-box / Raw / JSON 渲染
│   ├── services/
│   │   ├── sources.ts        # 数据源刷新逻辑
│   │   ├── subscriptions.ts  # 订阅生成 + 令牌
│   │   ├── auth.ts           # 会话 / CSRF / 限流
│   │   └── audit.ts          # 审计日志
│   ├── security/
│   │   ├── crypto.ts         # AES-GCM / HMAC / SHA-256
│   │   ├── password.ts       # PBKDF2
│   │   └── safe-fetch.ts     # SSRF 防护
│   └── db/
│       └── schema.ts         # Drizzle schema
├── dashboard/
│   ├── App.tsx               # 管理 SPA
│   ├── api.ts                # API 客户端
│   └── styles.css
migrations/
└── 0001_initial.sql          # D1 初始迁移
```

## 开发

```bash
npm run dev        # 本地开发 (Wrangler dev)
npm run build      # 构建前端
npm run lint       # ESLint
npm run typecheck  # TypeScript 类型检查
npm test           # Vitest 单元 + 集成测试
```

## License

MIT
