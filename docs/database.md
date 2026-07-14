# 数据库设计

权威结构位于 `migrations/0001_initial.sql`，`src/worker/db/schema.ts` 提供对应的 Drizzle schema。Wrangler 负责记录已应用 migration；发布后不要重写历史 migration。

| 表 | 用途 |
| --- | --- |
| `admins` | 单管理员身份与密码派生值 |
| `sessions` | HMAC 后的会话令牌、CSRF 值与有效期 |
| `settings` | 小型 JSON 系统设置 |
| `sources` | 数据源元数据和加密载荷 |
| `source_fetch_logs` | 刷新结果、耗时和脱敏错误 |
| `nodes` | 标准化节点、指纹、启停覆盖和当前快照状态 |
| `templates` | 输出模板扩展点 |
| `subscriptions` | 组合规则、目标格式、缓存 TTL 与 revision |
| `subscription_sources` | 订阅与数据源多对多关系 |
| `subscription_tokens` | HMAC 后的访问令牌和一次性展示前缀 |
| `audit_logs` | 管理修改与请求 ID |

节点刷新使用 `present` 标记当前上游快照。先将一个源的节点标为不在场，再按 `(source_id, fingerprint)` upsert 新快照；订阅只查询 `present = 1`。这样可以保留管理员的启停状态，同时避免已从上游移除的节点继续分发。

订阅缓存不保存于 D1。任何影响输出的更新都会增加 `subscriptions.revision`，旧 KV 键自然过期，无需同步扫描删除。
