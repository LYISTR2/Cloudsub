# CloudSub

[![CI](https://github.com/LYISTR2/Cloudsub/actions/workflows/ci.yml/badge.svg)](https://github.com/LYISTR2/Cloudsub/actions/workflows/ci.yml)
[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/LYISTR2/Cloudsub)

CloudSub 是一个部署在 Cloudflare Workers 上的自托管订阅配置管理与分发系统。它从你拥有或已获授权的配置中导入节点，完成解析、去重、组合和格式转换，再通过带令牌的地址分发。

CloudSub **不创建、出售或运行网络节点**，不提供扫描、探针、代理进程安装、套餐计费或第三方访问控制绕过能力。

## 当前版本

`0.1.0` 提供一条完整的 MVP 链路：

- 单管理员初始化、PBKDF2 密码哈希、HMAC 令牌索引、D1 会话、HttpOnly Cookie 与 CSRF 防护
- HTTPS URL 与手动数据源；完整上游 URL、敏感请求头和手动原文使用 AES-GCM 加密
- Clash/Mihomo YAML、Base64 URI 列表、常见单行 URI、内部 JSON 输入适配器
- 节点标准化、稳定指纹、单源去重、筛选、启停与标签
- 多数据源组合订阅、256 位随机令牌、只存令牌哈希、令牌轮换
- Raw Base64、Mihomo YAML、内部 JSON 输出适配器
- KV 修订号缓存、ETag、条件请求和统一的无效令牌响应
- 30 分钟 Cron 扫描、手动/定时刷新共用业务服务、审计与刷新日志
- React 管理控制台、D1 migrations、Workers Vitest 测试和 GitHub Actions CI

协议输入目前重点覆盖 `ss`、`vmess`、`vless`、`trojan`、`hysteria2` 与 `tuic` 的常用字段。复杂插件、非标准 URI 和第二阶段输出格式尚不保证完整保真。

## 一键部署

点击顶部的 **Deploy to Cloudflare** 按钮。Cloudflare 会从公开仓库创建 Worker，并根据 `wrangler.jsonc` 自动配置 D1 与 KV。

部署时需要提供两个互不相同的随机密钥：

```bash
openssl rand -base64 32 # APP_SECRET
openssl rand -base64 32 # DATA_ENCRYPTION_KEY
```

可选设置 `INITIAL_ADMIN_TOKEN`，为首次初始化增加一个部署侧令牌。部署脚本会先构建前端、对 `DB` 绑定应用 migrations，再部署 Worker。完成后访问 Worker 地址并在 `/setup` 创建管理员。

> 密钥丢失后，加密的数据源原文无法恢复。请使用 Cloudflare Secrets 安全保存，并建立账户侧备份流程。

## 本地开发

要求 Node.js 22.12 或更高版本。

```bash
npm install
cp .dev.vars.example .dev.vars
# 编辑 .dev.vars，填入两个独立随机密钥
npm run db:migrate
npm run dev
```

`npm run dev` 会先构建 React 静态资源，再由 Wrangler 启动包含 D1、KV 和 Assets 的本地 Worker。只开发界面时可另用 `npm run dev:ui`；Vite 会把 API 请求代理到 `8787` 端口。

常用检查：

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

## 公共订阅接口

```text
GET /sub/{token}
GET /sub/{token}?target=raw
GET /sub/{token}?target=mihomo
GET /sub/{token}?target=json
```

完整管理 API 见 [docs/api.md](docs/api.md)。部署、架构与安全说明分别见：

- [部署说明](docs/deployment.md)
- [系统架构](docs/architecture.md)
- [数据库设计](docs/database.md)
- [安全模型](docs/security.md)
- [开发指南](docs/development.md)

## 技术栈

Cloudflare Workers + Hono + TypeScript、React + Vite、D1、KV、Drizzle schema、Zod、Vitest Workers pool。仓库保持单包、单 Worker、前后端一体部署，以兼容 Deploy to Cloudflare。

## 合规与使用边界

你只能导入并分发自己拥有或已明确获授权使用的配置。禁止使用本项目从事未经授权的访问、公共节点采集、凭据滥用或违反适用法律与服务条款的活动。部署者对导入内容、访问令牌管理和实际使用方式负责。

## License

[MIT](LICENSE)
