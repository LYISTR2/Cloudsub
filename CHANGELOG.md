# Changelog

本项目遵循语义化版本（SemVer）。

## [0.2.0] - 2026-07-26

本次为一次结合上游 GitHub 仓库的优化升级，聚焦「Bug 修复 + 安全加固」「性能与代码质量」「文档与部署体验」三个方向，未改变对外 API 与订阅地址格式，向后兼容。

### 安全加固（Security）

- **修复 IPv6 SSRF 绕过**：`https://[::ffff:127.0.0.1]/` 这类 IPv4-mapped 地址经 WHATWG URL 解析后会被压缩成十六进制（`::ffff:7f00:1`），此前的 `::ffff:` 前缀检查只识别点分十进制形式，导致回环/私有地址可被绕过。现改为完整展开 IPv6，并识别 IPv4-mapped、IPv4-compatible 与 NAT64（`64:ff9b::/96`）中内嵌的 IPv4 后再做私有范围判定。
- **IPv4 编码归一化（纵深防御）**：新增 `canonicalizeIpv4()`，按 `inet_aton` 规则解析十进制整数、十六进制、八进制与短式 IP，配合 URL 解析器共同封堵编码绕过。
- 更新 `docs/security.md`，补充上述归一化规则说明。

### Bug 修复（Fixes）

- **Drizzle schema**：`subscriptions.default_target` 枚举补齐 `singbox`，与运行时 Zod 校验、渲染器保持一致（此前类型层缺失 `singbox`）。

### 性能与代码质量（Performance & Refactor）

- **路由分层重构**：将 526 行的 `src/worker/app.ts` 拆分为 `routes/{public,account,sources,nodes,subscriptions,system}.ts`，并抽出 `http.ts`（请求辅助函数）与 `validation.ts`（集中 Zod 校验）。注册顺序与鉴权/CSRF 中间件语义完全保持不变，运行时行为零变化。
- **新增覆盖索引（migration `0002`）**：
  - `nodes(source_id, present, enabled)` — 覆盖订阅生成时最热的过滤路径。
  - `subscription_tokens(subscription_id, enabled, created_at)` — 加速列表视图中「每个订阅的最新可用令牌」查询。

### 测试（Tests）

- 新增 SSRF 用例：编码/短式 IPv4、IPv4-mapped / NAT64 IPv6 的拦截与放行断言，以及 `canonicalizeIpv4()` 单元测试。

### 文档（Docs）

- 新增 `CHANGELOG.md` 与 `docs/upgrade-notes.md`（升级与迁移说明）。
- `README.md` 更新项目结构、安全特性说明与版本号。

### 升级须知

- 部署新版本请执行 `npm run db:migrate:remote`（或部署脚本会自动应用）以创建 `0002` 索引。索引为纯增量、可安全应用于既有数据库。

## [0.1.0]

- 初始版本：Cloudflare Workers 订阅节点管理与分发系统。
