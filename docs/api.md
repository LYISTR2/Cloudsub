# API 概览

所有 JSON 成功响应使用 `{ "data": ... }`，错误使用 `{ "error": { "code", "message", "requestId" } }`。除系统状态、初始化、登录和公共订阅外，`/api/*` 都需要管理员会话；非只读请求还需要 CSRF 头。

## 公共

```text
GET /health
GET /sub/:token?target=raw|mihomo|json
```

订阅响应包含 `Content-Type`、`ETag`、`Cache-Control`、`Content-Disposition` 与 `Profile-Update-Interval`，支持 `If-None-Match`。

## 初始化与认证

```text
GET  /api/system/status
POST /api/system/initialize
POST /api/auth/login
GET  /api/auth/session
POST /api/auth/logout
PUT  /api/auth/password
```

## 管理

```text
GET    /api/dashboard
GET    /api/sources
POST   /api/sources
GET    /api/sources/:id
PUT    /api/sources/:id
DELETE /api/sources/:id
POST   /api/sources/:id/refresh
GET    /api/sources/:id/logs

GET  /api/nodes
GET  /api/nodes/:id
PUT  /api/nodes/:id
POST /api/nodes/batch

GET    /api/subscriptions
POST   /api/subscriptions
GET    /api/subscriptions/:id
PUT    /api/subscriptions/:id
DELETE /api/subscriptions/:id
POST   /api/subscriptions/:id/preview
POST   /api/subscriptions/:id/rotate-token
POST   /api/subscriptions/:id/invalidate-cache

GET /api/settings
PUT /api/settings
GET /api/audit-logs
```

列表接口使用 `page` 与 `pageSize`，最大每页 100 条。节点列表额外支持 `q`、`protocol` 与 `sourceId`。
