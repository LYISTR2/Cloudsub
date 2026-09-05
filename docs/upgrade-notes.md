# 升级说明（0.1.0 → 0.2.0）

本文件记录本次优化升级的内容、原因与升级步骤，方便你在自己的 Cloudflare 账户上平滑更新。

## 一句话总结

在不改变对外接口与订阅地址格式的前提下，修复了一处真实的 IPv6 SSRF 绕过、补齐了一个 schema 枚举缺失、对 Worker 路由做了分层重构，并新增两条覆盖索引提升订阅生成与列表查询性能。

## 近期未发布改进

后续提交新增 `0003_source_kind` 和 `0004_refresh_safety` 两条**纯增量** migration：前者区分订阅源与单节点源，后者增加刷新租约和节点 staging 表。升级前必须运行：

```bash
npm run db:migrate:remote
```

升级后的关键语义：停用数据源会立即停止其节点分发；手动刷新绕过定时刷新冷却但仍受每源租约保护；定时刷新在 30 秒冷却期内跳过重复工作。新生成的 Sing-box 配置目标为 1.14.x，Mihomo 配置目标为 1.19.x。

## 变更清单

### 1. 安全：修复 IPv6 SSRF 绕过（重点）

- **现象**：创建「URL 数据源」时，形如 `https://[::ffff:127.0.0.1]/` 的地址在 WHATWG URL 解析后 `hostname` 会变成 `[::ffff:7f00:1]`（IPv4 段被压缩为十六进制）。旧版 `isBlockedIpv6` 仅处理 `::ffff:` 后跟点分十进制的情况，因此该回环/私有地址未被拦截。
- **修复**：`src/worker/security/safe-fetch.ts` 现完整展开 IPv6，识别 IPv4-mapped（`::ffff:x`）、IPv4-compatible（`::x`）与 NAT64（`64:ff9b::/96`）中内嵌的 IPv4，再对映射地址执行私有/保留范围判定。
- **纵深防御**：新增并导出 `canonicalizeIpv4()`，按 `inet_aton` 规则解析十进制整数、十六进制、八进制与短式 IPv4，与 URL 解析器叠加封堵编码绕过。

### 2. Bug：补齐 `default_target` 枚举

`src/worker/db/schema.ts` 中 `subscriptions.default_target` 之前的枚举为 `['raw','mihomo','json']`，缺少 `singbox`。运行时 Zod 校验与渲染器一直支持 `singbox`，此处仅为类型层不一致，现已补齐。数据库层无 CHECK 约束，无需数据迁移。

### 3. 重构：Worker 路由分层

`src/worker/app.ts`（原 526 行）拆分为：

```
src/worker/
├── app.ts                 # 仅负责组装：中间件 + 顺序挂载各路由 + 错误处理
├── http.ts                # body()/pageParams()/slugify()/maskServer() 等请求辅助
├── validation.ts          # 集中的 Zod 请求体 schema
└── routes/
    ├── public.ts          # 健康检查、系统初始化、登录、/sub 订阅下载（免鉴权）
    ├── account.ts         # 会话 / 登出 / 改密
    ├── sources.ts         # 数据源 CRUD / 刷新 / 日志
    ├── nodes.ts           # 节点查询 / 更新 / 批量
    ├── subscriptions.ts   # 订阅 CRUD / 预览 / 令牌轮换 / 缓存失效
    └── system.ts          # 概览 / 设置 / 审计日志
```

关键点：**注册顺序被严格保留** —— 免鉴权路由在 `requireAuth` / `requireCsrf` 中间件之前注册，其余全部在其后。因此鉴权与 CSRF 语义、以及未匹配 `/api/*` 返回 401 的行为均无变化。

### 4. 性能：新增覆盖索引（migration `0002`）

- `nodes(source_id, present, enabled)`：订阅生成查询 `... WHERE ss.subscription_id=? AND n.enabled=1 AND n.present=1` 的最热过滤路径。
- `subscription_tokens(subscription_id, enabled, created_at)`：列表视图中「每个订阅的最新可用令牌」相关子查询。

索引为纯增量、幂等（`CREATE INDEX IF NOT EXISTS`），可安全应用于既有数据库。

## 升级步骤

```bash
git pull            # 或以本压缩包内容覆盖你的工作副本
npm ci
npm run lint
npm run typecheck
npm test            # 含新增 SSRF / IPv4 归一化用例
npm run build
npm run deploy      # 部署脚本会自动执行 db:migrate:remote 应用 0002 索引
```

若只想单独应用数据库迁移：

```bash
npx wrangler d1 migrations apply cloudsub --remote
```

## 兼容性

- 对外 REST API、订阅地址格式（`/sub/<token>?target=...`）、Cookie 名称与加密格式均未改变。
- 无破坏性数据迁移，可直接在既有部署上滚动升级。
