# 安全模型

## 管理认证

- 密码使用 PBKDF2-HMAC-SHA-256、随机 128 位盐和 210,000 次迭代。
- 会话令牌为 256 位随机值，D1 只保存使用 `APP_SECRET` 计算的 HMAC-SHA-256。
- 浏览器使用 HttpOnly、SameSite=Strict Cookie；生产 HTTPS 下同时设置 Secure。
- 写操作同时校验 Origin、CSRF Cookie、`X-CSRF-Token` 和会话内 CSRF 值。
- 登录失败记录在 KV，连续失败触发 15 分钟短期锁定。

## 订阅令牌

订阅令牌至少 256 位，只在创建或轮换时返回一次。数据库仅保存 HMAC-SHA-256 和八字符前缀。无效、停用和过期令牌统一返回 `subscription_unavailable`，避免暴露对象是否存在。更换 `APP_SECRET` 会主动使已有会话和订阅令牌失效。

## 上游拉取

安全拉取模块实施：

- 只允许 HTTPS，禁止 URL 用户名和密码。
- 拒绝 localhost、`.internal`、私有 IP、链路本地、运营商 NAT、基准测试和组播/保留 IP 字面量。
- 手动处理最多三次重定向，每次都重新验证目标。
- 超时与响应体上限；流式读取过程中再次执行大小检查。
- 不透传管理 Cookie、Host、代理鉴权、`CF-*`、`Sec-*` 和转发链请求头。
- 每个源设置刷新冷却；错误日志只保存经过截断的公开错误信息。

域名解析和最终网络路由仍由 Cloudflare Workers 平台执行。若未来接入 Private Network、Service Binding 或自定义出站代理，必须增加解析后地址校验与网络级 egress allowlist，不能只复用当前公共 Internet 假设。

## 数据保护

完整上游 URL（可能包含查询令牌）、手动原文与自定义上游请求头使用 AES-256-GCM 加密，普通 `url` 列只保存去掉查询内容的展示值。节点配置为完成订阅再生成而保存在 D1 中，因此数据库本身和 Cloudflare 账户访问权限仍属于安全边界。后台列表默认对服务器地址脱敏，并且不返回节点凭据或完整原始 URI。

## 浏览器与 API

Worker 为所有响应设置 CSP、`X-Content-Type-Options`、`X-Frame-Options`、Referrer Policy 与 Permissions Policy。管理 API 不发送跨域许可头。所有修改都写入审计日志并附带请求 ID。

## 报告漏洞

请不要在公开 Issue 中提交真实订阅、访问令牌、密钥或可复现凭据。先创建不含敏感材料的安全问题说明，由维护者提供私密沟通渠道。
