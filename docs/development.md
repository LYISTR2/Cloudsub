# 开发指南

## 原则

- 路由只负责 HTTP 输入输出；业务逻辑进入 `services`。
- 输入和输出协议必须通过适配器扩展。
- 数据库变更必须新增 migration，不修改已经发布的 migration。
- 不在日志、测试夹具或快照中放入真实凭据。
- 新功能至少补充纯逻辑单测；跨 D1、KV、Cookie 的路径补充 Workers 集成测试。

## 测试

Vitest 通过 `@cloudflare/vitest-pool-workers` 在 workerd/Miniflare 中运行。配置会读取真实 Wrangler 绑定，并把 migrations 注入测试环境。`tests/integration/api.test.ts` 覆盖完整生命周期，单元测试覆盖解析器、渲染器、密码、加密和 URL 拒绝规则。

## 添加解析器

1. 在 `src/worker/adapters/input` 新增只处理一种格式的模块。
2. 输出统一 `NormalizedNode`，使用 `completeNode` 生成指纹。
3. 设置输入数量、深度和大小边界。
4. 在 `index.ts` 的适配器列表中按确定性顺序接入。
5. 添加正常输入、恶意/损坏输入和去重测试。

## 添加渲染器

渲染器接收已经过滤和重命名的节点，不执行数据库查询。新增目标时同步更新共享 target 类型、API 验证、内容类型、扩展名、README 和集成测试。
