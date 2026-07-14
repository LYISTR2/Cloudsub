import { useCallback, useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { api, ApiError } from "./api";

type Notice = { tone: "success" | "error"; text: string } | null;

interface SystemStatus {
  initialized: boolean;
  migrationsReady: boolean;
  secretsConfigured: boolean;
  setupTokenRequired: boolean;
}

interface Session {
  username: string;
  csrfToken: string;
}

interface Source {
  id: string;
  name: string;
  type: "url" | "manual";
  url: string | null;
  enabled: number;
  node_count: number;
  refresh_interval: number;
  last_success_at: string | null;
  last_error: string | null;
}

interface NodeItem {
  id: string;
  name: string;
  protocol: string;
  server: string;
  port: number;
  source_name: string;
  enabled: number;
  tags: string[];
}

interface Subscription {
  id: string;
  name: string;
  slug: string;
  enabled: number;
  default_target: string;
  token_prefix: string | null;
  sourceIds: string[];
  last_access_at: string | null;
}

const navigation = [
  { path: "/dashboard", label: "概览", icon: "◫" },
  { path: "/sources", label: "数据源", icon: "↗" },
  { path: "/nodes", label: "节点", icon: "◉" },
  { path: "/subscriptions", label: "订阅", icon: "⌁" },
  { path: "/logs", label: "日志", icon: "≡" },
  { path: "/settings", label: "设置", icon: "⚙" },
];

function formatTime(value: string | null | undefined): string {
  if (!value) return "尚无记录";
  return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

function NoticeBar({ notice, onClose }: { notice: Notice; onClose: () => void }) {
  if (!notice) return null;
  return <div className={"notice " + notice.tone}><span>{notice.text}</span><button onClick={onClose}>×</button></div>;
}

function Logo() {
  return <div className="logo"><span className="logo-mark">C</span><span><strong>CloudSub</strong><small>EDGE SUBSCRIPTIONS</small></span></div>;
}

function AuthFrame({ eyebrow, title, description, children }: { eyebrow: string; title: string; description: string; children: ReactNode }) {
  return (
    <main className="auth-shell">
      <section className="auth-story">
        <Logo />
        <div className="story-copy">
          <p className="eyebrow">{eyebrow}</p>
          <h1>让配置流动，<br />让边缘保持简单。</h1>
          <p>一个部署在 Cloudflare Workers 上的自托管订阅配置管理器。只管理你有权使用的配置。</p>
        </div>
        <div className="story-status"><span className="pulse" /> D1 + KV · 单 Worker 架构</div>
      </section>
      <section className="auth-panel">
        <div className="auth-card">
          <p className="eyebrow">{eyebrow}</p>
          <h2>{title}</h2>
          <p className="muted">{description}</p>
          {children}
        </div>
      </section>
    </main>
  );
}

function SetupPage({ status, onReady }: { status: SystemStatus; onReady: (session: Session) => void }) {
  const [notice, setNotice] = useState<Notice>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ username: "admin", password: "", setupToken: "" });
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setNotice(null);
    try {
      const session = await api<Session>("/api/system/initialize", { method: "POST", body: form });
      onReady(session);
    } catch (error) {
      setNotice({ tone: "error", text: error instanceof Error ? error.message : "初始化失败" });
    } finally { setBusy(false); }
  }
  return (
    <AuthFrame eyebrow="首次初始化" title="创建管理员" description="此账户只保存在你的 D1 数据库中。密码至少 12 位。">
      <NoticeBar notice={notice} onClose={() => setNotice(null)} />
      {!status.migrationsReady && <div className="callout error">数据库迁移尚未应用。请先运行部署脚本或 `npm run db:migrate`。</div>}
      {!status.secretsConfigured && <div className="callout error">请先配置 APP_SECRET 和 DATA_ENCRYPTION_KEY。</div>}
      <form className="stack" onSubmit={submit}>
        <label>管理员用户名<input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} autoComplete="username" required /></label>
        <label>密码<input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} autoComplete="new-password" minLength={12} required /></label>
        {status.setupTokenRequired && <label>初始化令牌<input type="password" value={form.setupToken} onChange={(event) => setForm({ ...form, setupToken: event.target.value })} required /></label>}
        <button className="button primary wide" disabled={busy || !status.migrationsReady || !status.secretsConfigured}>{busy ? "正在初始化…" : "完成初始化"}</button>
      </form>
    </AuthFrame>
  );
}

function LoginPage({ onReady }: { onReady: (session: Session) => void }) {
  const [notice, setNotice] = useState<Notice>(null);
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ username: "", password: "" });
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setNotice(null);
    try { onReady(await api<Session>("/api/auth/login", { method: "POST", body: form })); }
    catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "登录失败" }); }
    finally { setBusy(false); }
  }
  return (
    <AuthFrame eyebrow="管理控制台" title="欢迎回来" description="使用管理员账户继续。会话保存在安全的 HttpOnly Cookie 中。">
      <NoticeBar notice={notice} onClose={() => setNotice(null)} />
      <form className="stack" onSubmit={submit}>
        <label>用户名<input value={form.username} onChange={(event) => setForm({ ...form, username: event.target.value })} autoComplete="username" autoFocus required /></label>
        <label>密码<input type="password" value={form.password} onChange={(event) => setForm({ ...form, password: event.target.value })} autoComplete="current-password" required /></label>
        <button className="button primary wide" disabled={busy}>{busy ? "正在验证…" : "登录"}</button>
      </form>
    </AuthFrame>
  );
}

function Shell({ session, path, navigate, logout, children }: { session: Session; path: string; navigate: (path: string) => void; logout: () => void; children: ReactNode }) {
  const active = navigation.find((item) => path.startsWith(item.path)) ?? navigation[0];
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <Logo />
        <nav>{navigation.map((item) => <button key={item.path} className={path.startsWith(item.path) ? "active" : ""} onClick={() => navigate(item.path)}><span>{item.icon}</span>{item.label}</button>)}</nav>
        <div className="sidebar-foot"><div className="avatar">{session.username.slice(0, 1).toUpperCase()}</div><div><strong>{session.username}</strong><small>系统管理员</small></div><button className="icon-button" title="退出" onClick={logout}>↪</button></div>
      </aside>
      <main className="content">
        <header className="topbar"><div><p className="eyebrow">CloudSub Console</p><h1>{active.label}</h1></div><div className="edge-state"><span className="pulse" /> Edge online</div></header>
        {children}
      </main>
    </div>
  );
}

function DashboardPage() {
  const [data, setData] = useState<{ counts: { sources: number; nodes: number; subscriptions: number }; recentErrors: Array<{ name: string; error: string; created_at: string }>; lastSubscriptionAccess: string | null }>();
  useEffect(() => { void api<typeof data>("/api/dashboard").then(setData); }, []);
  const cards = [
    { label: "启用数据源", value: data?.counts.sources ?? "—", note: "持续同步", color: "green" },
    { label: "有效节点", value: data?.counts.nodes ?? "—", note: "已标准化", color: "blue" },
    { label: "有效订阅", value: data?.counts.subscriptions ?? "—", note: "令牌保护", color: "purple" },
  ];
  return <div className="page-grid">
    <section className="hero-card"><div><p className="eyebrow">系统状态</p><h2>你的配置，运行在边缘。</h2><p>从导入、解析到分发，所有数据都留在你的 Cloudflare 账户中。</p></div><div className="orbit"><span>C</span></div></section>
    <section className="stats">{cards.map((card) => <article className="stat-card" key={card.label}><span className={"stat-dot " + card.color} /><p>{card.label}</p><strong>{card.value}</strong><small>{card.note}</small></article>)}</section>
    <section className="panel span-two"><div className="panel-head"><div><p className="eyebrow">运行摘要</p><h3>最近状态</h3></div><span className="status-pill good">自动刷新已启用</span></div>
      <div className="summary-row"><span>最近订阅访问</span><strong>{formatTime(data?.lastSubscriptionAccess)}</strong></div>
      <div className="summary-row"><span>定时刷新</span><strong>每 30 分钟 · UTC</strong></div>
      <div className="summary-row"><span>最近错误</span><strong>{data?.recentErrors.length ? data.recentErrors.length + " 条" : "无"}</strong></div>
      {data?.recentErrors.map((item) => <div className="error-row" key={item.created_at}><span>{item.name}</span><p>{item.error}</p><time>{formatTime(item.created_at)}</time></div>)}
    </section>
  </div>;
}

function SourcesPage() {
  const [items, setItems] = useState<Source[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [busyId, setBusyId] = useState<string>();
  const [form, setForm] = useState({ name: "", type: "url" as "url" | "manual", url: "", content: "", refreshInterval: 60 });
  const load = useCallback(async () => { const result = await api<{ items: Source[] }>("/api/sources?pageSize=100"); setItems(result.items); }, []);
  useEffect(() => { void load(); }, [load]);
  async function create(event: FormEvent) {
    event.preventDefault(); setNotice(null);
    try {
      const result = await api<{ refreshError?: string }>("/api/sources", { method: "POST", body: { ...form, timeoutMs: 15000, enabled: true } });
      setNotice({ tone: result.refreshError ? "error" : "success", text: result.refreshError ?? "数据源已创建并完成解析" });
      setForm({ name: "", type: "url", url: "", content: "", refreshInterval: 60 }); setShowForm(false); await load();
    } catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "创建失败" }); }
  }
  async function refresh(id: string) {
    setBusyId(id); setNotice(null);
    try { const result = await api<{ nodeCount: number }>("/api/sources/" + id + "/refresh", { method: "POST" }); setNotice({ tone: "success", text: "刷新完成，共解析 " + result.nodeCount + " 个节点" }); await load(); }
    catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "刷新失败" }); }
    finally { setBusyId(undefined); }
  }
  async function remove(id: string) {
    if (!window.confirm("删除数据源及其节点？此操作无法撤销。")) return;
    await api("/api/sources/" + id, { method: "DELETE" }); await load();
  }
  return <section className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">Upstream registry</p><h2>数据源</h2><p className="muted">导入你拥有或已获授权的 HTTPS 订阅与手动配置。</p></div><button className="button primary" onClick={() => setShowForm(!showForm)}>{showForm ? "取消" : "+ 添加数据源"}</button></div>
    <NoticeBar notice={notice} onClose={() => setNotice(null)} />
    {showForm && <form className="form-card" onSubmit={create}>
      <div className="form-grid"><label>名称<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="例如：主订阅" required /></label><label>类型<select value={form.type} onChange={(event) => setForm({ ...form, type: event.target.value as "url" | "manual" })}><option value="url">HTTPS URL</option><option value="manual">手动配置</option></select></label></div>
      {form.type === "url" ? <label>上游地址<input type="url" value={form.url} onChange={(event) => setForm({ ...form, url: event.target.value })} placeholder="https://example.com/subscription" required /></label> : <label>配置内容<textarea rows={8} value={form.content} onChange={(event) => setForm({ ...form, content: event.target.value })} placeholder="粘贴 Clash YAML、URI 列表或内部 JSON" required /></label>}
      <div className="form-actions"><label className="compact">刷新周期（分钟）<input type="number" min={5} value={form.refreshInterval} onChange={(event) => setForm({ ...form, refreshInterval: Number(event.target.value) })} /></label><button className="button primary">保存并解析</button></div>
    </form>}
    <div className="table-wrap"><table><thead><tr><th>数据源</th><th>类型</th><th>节点</th><th>最近成功</th><th>状态</th><th /></tr></thead><tbody>
      {items.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.url ?? "手动内容 · 已加密"}</small></td><td><span className="protocol">{item.type}</span></td><td>{item.node_count ?? 0}</td><td>{formatTime(item.last_success_at)}</td><td>{item.last_error ? <span className="status-pill bad" title={item.last_error}>异常</span> : <span className="status-pill good">正常</span>}</td><td className="actions"><button className="button ghost small" disabled={busyId === item.id} onClick={() => void refresh(item.id)}>{busyId === item.id ? "刷新中" : "刷新"}</button><button className="button danger small" onClick={() => void remove(item.id)}>删除</button></td></tr>)}
      {!items.length && <tr><td colSpan={6}><div className="empty">还没有数据源。添加第一个上游或手动配置开始。</div></td></tr>}
    </tbody></table></div>
  </section>;
}

function NodesPage() {
  const [items, setItems] = useState<NodeItem[]>([]);
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("");
  const [notice, setNotice] = useState<Notice>(null);
  const load = useCallback(async () => { const params = new URLSearchParams({ pageSize: "100", q: query, protocol }); const result = await api<{ items: NodeItem[] }>("/api/nodes?" + params); setItems(result.items); }, [query, protocol]);
  useEffect(() => { const timer = setTimeout(() => void load(), 180); return () => clearTimeout(timer); }, [load]);
  async function toggle(item: NodeItem) {
    try { await api("/api/nodes/" + item.id, { method: "PUT", body: { enabled: !item.enabled } }); await load(); }
    catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "更新失败" }); }
  }
  return <section className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">Normalized inventory</p><h2>节点</h2><p className="muted">敏感字段默认脱敏；禁用状态会在上游刷新后保留。</p></div><span className="status-pill neutral">{items.length} 条当前结果</span></div>
    <NoticeBar notice={notice} onClose={() => setNotice(null)} />
    <div className="filters"><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索节点名称" /><select value={protocol} onChange={(event) => setProtocol(event.target.value)}><option value="">全部协议</option>{["ss", "vmess", "vless", "trojan", "hysteria2", "tuic"].map((value) => <option key={value}>{value}</option>)}</select></div>
    <div className="table-wrap"><table><thead><tr><th>名称</th><th>协议</th><th>服务器</th><th>来源</th><th>启用</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td><strong>{item.name}</strong>{item.tags.length > 0 && <small>{item.tags.join(" · ")}</small>}</td><td><span className="protocol">{item.protocol}</span></td><td className="mono">{item.server}:{item.port}</td><td>{item.source_name}</td><td><button className={"switch " + (item.enabled ? "on" : "")} onClick={() => void toggle(item)}><span /></button></td></tr>)}{!items.length && <tr><td colSpan={5}><div className="empty">没有匹配的节点。先刷新一个数据源。</div></td></tr>}</tbody></table></div>
  </section>;
}

function SubscriptionsPage() {
  const [items, setItems] = useState<Subscription[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  const [tokenUrl, setTokenUrl] = useState("");
  const [preview, setPreview] = useState<{ body: string; nodeCount: number }>();
  const [form, setForm] = useState({ name: "", sourceIds: [] as string[], defaultTarget: "mihomo" });
  const load = useCallback(async () => { const [subscriptionData, sourceData] = await Promise.all([api<{ items: Subscription[] }>("/api/subscriptions?pageSize=100"), api<{ items: Source[] }>("/api/sources?pageSize=100")]); setItems(subscriptionData.items); setSources(sourceData.items); }, []);
  useEffect(() => { void load(); }, [load]);
  async function create(event: FormEvent) {
    event.preventDefault(); setNotice(null);
    try {
      const result = await api<{ token: string }>("/api/subscriptions", { method: "POST", body: { ...form, enabled: true, cacheTtl: 300, rules: {} } });
      setTokenUrl(window.location.origin + "/sub/" + result.token); setNotice({ tone: "success", text: "订阅已创建。完整令牌只显示这一次。" }); setShowForm(false); setForm({ name: "", sourceIds: [], defaultTarget: "mihomo" }); await load();
    } catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "创建失败" }); }
  }
  async function rotate(item: Subscription) {
    if (!window.confirm("旧订阅地址将立即失效，继续轮换令牌？")) return;
    const result = await api<{ token: string }>("/api/subscriptions/" + item.id + "/rotate-token", { method: "POST" }); setTokenUrl(window.location.origin + "/sub/" + result.token); setNotice({ tone: "success", text: "令牌已轮换，请立即保存新地址。" }); await load();
  }
  async function showPreview(item: Subscription) { setPreview(await api<{ body: string; nodeCount: number }>("/api/subscriptions/" + item.id + "/preview", { method: "POST", body: { target: item.default_target } })); }
  return <section className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">Tokenized delivery</p><h2>订阅</h2><p className="muted">组合多个数据源，通过不可猜测令牌安全分发。</p></div><button className="button primary" onClick={() => setShowForm(!showForm)}>{showForm ? "取消" : "+ 创建订阅"}</button></div>
    <NoticeBar notice={notice} onClose={() => setNotice(null)} />
    {tokenUrl && <div className="token-reveal"><div><p className="eyebrow">仅显示一次</p><strong>{tokenUrl}</strong></div><button className="button primary" onClick={() => void navigator.clipboard.writeText(tokenUrl)}>复制地址</button></div>}
    {showForm && <form className="form-card" onSubmit={create}><div className="form-grid"><label>名称<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="例如：日常设备" required /></label><label>默认格式<select value={form.defaultTarget} onChange={(event) => setForm({ ...form, defaultTarget: event.target.value })}><option value="mihomo">Mihomo YAML</option><option value="raw">Raw Base64</option><option value="json">内部 JSON</option></select></label></div><fieldset><legend>包含的数据源</legend><div className="check-grid">{sources.map((source) => <label className="check" key={source.id}><input type="checkbox" checked={form.sourceIds.includes(source.id)} onChange={(event) => setForm({ ...form, sourceIds: event.target.checked ? [...form.sourceIds, source.id] : form.sourceIds.filter((id) => id !== source.id) })} />{source.name}</label>)}</div></fieldset><div className="form-actions"><span className="muted">创建后可继续配置过滤、重命名与排序规则。</span><button className="button primary" disabled={!form.sourceIds.length}>创建并生成令牌</button></div></form>}
    <div className="card-list">{items.map((item) => <article className="subscription-card" key={item.id}><div className="sub-icon">⌁</div><div className="sub-copy"><div><h3>{item.name}</h3><span className={"status-pill " + (item.enabled ? "good" : "neutral")}>{item.enabled ? "运行中" : "已暂停"}</span></div><p><span className="protocol">{item.default_target}</span> · {item.sourceIds.length} 个数据源 · 令牌 {item.token_prefix ?? "—"}••••</p><small>最近访问：{formatTime(item.last_access_at)}</small></div><div className="actions"><button className="button ghost small" onClick={() => void showPreview(item)}>预览</button><button className="button ghost small" onClick={() => void rotate(item)}>轮换令牌</button></div></article>)}{!items.length && <div className="empty">还没有订阅。选择数据源后创建第一条。</div>}</div>
    {preview && <div className="modal-backdrop" onClick={() => setPreview(undefined)}><div className="modal" onClick={(event) => event.stopPropagation()}><div className="panel-head"><div><p className="eyebrow">输出预览</p><h3>{preview.nodeCount} 个节点</h3></div><button className="icon-button" onClick={() => setPreview(undefined)}>×</button></div><pre>{preview.body}</pre></div></div>}
  </section>;
}

function LogsPage() {
  const [items, setItems] = useState<Array<{ id: string; action: string; target_type: string; username: string; created_at: string; request_id: string }>>([]);
  useEffect(() => { void api<{ items: typeof items }>("/api/audit-logs?pageSize=100").then((data) => setItems(data.items)); }, []);
  return <section className="panel page-panel"><div className="panel-head"><div><p className="eyebrow">Audit trail</p><h2>审计日志</h2><p className="muted">所有管理修改都会记录动作、目标和请求 ID。</p></div></div><div className="timeline">{items.map((item) => <div className="timeline-item" key={item.id}><span className="timeline-dot" /><div><strong>{item.action}</strong><p>{item.username ?? "system"} · {item.target_type ?? "system"}</p><small>{formatTime(item.created_at)} · {item.request_id?.slice(0, 8)}</small></div></div>)}{!items.length && <div className="empty">暂无审计记录。</div>}</div></section>;
}

function SettingsPage() {
  const [timezone, setTimezone] = useState("UTC");
  const [limits, setLimits] = useState<{ maxSourceBytes: number; sessionTtl: number; subscriptionCacheTtl: number }>();
  const [password, setPassword] = useState({ currentPassword: "", newPassword: "" });
  const [notice, setNotice] = useState<Notice>(null);
  useEffect(() => { void api<{ timezone?: string; limits: typeof limits }>("/api/settings").then((data) => { setTimezone(data.timezone ?? "UTC"); setLimits(data.limits); }); }, []);
  async function save(event: FormEvent) { event.preventDefault(); try { await api("/api/settings", { method: "PUT", body: { timezone } }); setNotice({ tone: "success", text: "系统设置已保存" }); } catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "保存失败" }); } }
  async function changePassword(event: FormEvent) { event.preventDefault(); try { await api("/api/auth/password", { method: "PUT", body: password }); setPassword({ currentPassword: "", newPassword: "" }); setNotice({ tone: "success", text: "密码已修改，其他会话已退出" }); } catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "修改失败" }); } }
  return <div className="settings-grid"><NoticeBar notice={notice} onClose={() => setNotice(null)} /><section className="panel"><div className="panel-head"><div><p className="eyebrow">Preferences</p><h2>系统设置</h2></div></div><form className="stack" onSubmit={save}><label>显示时区<input value={timezone} onChange={(event) => setTimezone(event.target.value)} placeholder="Asia/Shanghai" /></label><div className="setting-facts"><div><span>上游大小限制</span><strong>{limits ? Math.round(limits.maxSourceBytes / 1024 / 1024) + " MB" : "—"}</strong></div><div><span>订阅缓存</span><strong>{limits?.subscriptionCacheTtl ?? "—"} 秒</strong></div><div><span>会话有效期</span><strong>{limits ? Math.round(limits.sessionTtl / 86400) + " 天" : "—"}</strong></div></div><button className="button primary">保存设置</button></form></section><section className="panel"><div className="panel-head"><div><p className="eyebrow">Security</p><h2>修改密码</h2></div></div><form className="stack" onSubmit={changePassword}><label>当前密码<input type="password" value={password.currentPassword} onChange={(event) => setPassword({ ...password, currentPassword: event.target.value })} required /></label><label>新密码<input type="password" minLength={12} value={password.newPassword} onChange={(event) => setPassword({ ...password, newPassword: event.target.value })} required /></label><button className="button ghost">更新密码</button></form></section></div>;
}

export default function App() {
  const [status, setStatus] = useState<SystemStatus>();
  const [session, setSession] = useState<Session>();
  const [path, setPath] = useState(window.location.pathname);
  const [loading, setLoading] = useState(true);
  useEffect(() => {
    const listener = () => setPath(window.location.pathname);
    window.addEventListener("popstate", listener);
    return () => window.removeEventListener("popstate", listener);
  }, []);
  useEffect(() => {
    void (async () => {
      try {
        const system = await api<SystemStatus>("/api/system/status"); setStatus(system);
        if (system.initialized) {
          try { setSession(await api<Session>("/api/auth/session")); }
          catch (error) { if (!(error instanceof ApiError) || error.code !== "authentication_required") console.warn(error); }
        }
      } finally { setLoading(false); }
    })();
  }, []);
  function navigate(next: string) { window.history.pushState({}, "", next); setPath(next); }
  async function logout() { try { await api("/api/auth/logout", { method: "POST" }); } finally { setSession(undefined); navigate("/login"); } }
  if (loading || !status) return <div className="loading-screen"><Logo /><div className="loader" /></div>;
  if (!status.initialized) return <SetupPage status={status} onReady={(value) => { setSession(value); setStatus({ ...status, initialized: true }); navigate("/dashboard"); }} />;
  if (!session) return <LoginPage onReady={(value) => { setSession(value); navigate("/dashboard"); }} />;
  const route = path === "/" || path === "/login" || path === "/setup" ? "/dashboard" : path;
  let page: ReactNode;
  if (route.startsWith("/sources")) page = <SourcesPage />;
  else if (route.startsWith("/nodes")) page = <NodesPage />;
  else if (route.startsWith("/subscriptions")) page = <SubscriptionsPage />;
  else if (route.startsWith("/logs")) page = <LogsPage />;
  else if (route.startsWith("/settings")) page = <SettingsPage />;
  else page = <DashboardPage />;
  return <Shell session={session} path={route} navigate={navigate} logout={() => void logout()}>{page}</Shell>;
}
