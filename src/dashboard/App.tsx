import { useEffect, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { api, ApiError, onSessionExpired } from "./api";
import { copyText } from "./clipboard";
import { Modal, NoticeBar, Pagination, TokenReveal } from "./components";
import type { Notice } from "./components";
import { ListState } from "./components";
import { formatTime, useAsync, useBusy, useDebounced, usePagedList } from "./hooks";
import { validateSafePattern } from "../worker/security/regex";

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
  source_kind: "subscription" | "standalone";
  url: string | null;
  enabled: number;
  node_count: number;
  refresh_interval: number;
  last_success_at: string | null;
  last_error: string | null;
}

interface SourceOption {
  id: string;
  name: string;
  source_kind: "subscription" | "standalone";
  type: "url" | "manual";
  enabled: number;
}

interface NodeItem {
  id: string;
  name: string;
  protocol: string;
  server: string;
  port: number;
  source_name: string;
  source_kind: "subscription" | "standalone";
  enabled: number;
  tags: string[];
}

interface SubscriptionDetail {
  id: string;
  name: string;
  slug: string;
  enabled: number;
  default_target: SubscriptionTarget;
  expires_at: string | null;
  sourceIds: string[];
  rules: SubscriptionRules;
}

type SubscriptionTarget = "raw" | "mihomo" | "singbox" | "json";

interface SubscriptionRules {
  protocols?: string[];
  tags?: string[];
  includeName?: string;
  excludeName?: string;
  sortBy?: "name" | "protocol" | "source";
  rename?: Array<{ pattern: string; replacement: string }>;
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

interface SubscriptionFormState {
  name: string;
  sourceIds: string[];
  enabled: boolean;
  expiresAt: string;
  defaultTarget: SubscriptionTarget;
  protocols: string[];
  includeName: string;
  excludeName: string;
  sortBy: "name" | "protocol" | "source";
  rename: Array<{ pattern: string; replacement: string }>;
}

const EMPTY_FORM: SubscriptionFormState = {
  name: "", sourceIds: [], enabled: true, expiresAt: "", defaultTarget: "mihomo",
  protocols: [], includeName: "", excludeName: "", sortBy: "name", rename: [],
};

const navigation = [
  { path: "/dashboard", label: "概览", icon: "▸" },
  { path: "/sources", label: "数据源", icon: "↥" },
  { path: "/nodes", label: "节点", icon: "◉" },
  { path: "/subscriptions", label: "订阅", icon: "§" },
  { path: "/logs", label: "日志", icon: "≡" },
  { path: "/settings", label: "设置", icon: "∗" },
];

const PROTOCOLS = ["ss", "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls"];

function Logo() {
  return <div className="logo"><span className="logo-mark">C</span><span><strong>CloudSub</strong><small>EDGE SUBSCRIPTION OPS</small></span></div>;
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

function SetupPage({ status, onReady, notice, onNotice }: { status: SystemStatus; onReady: (session: Session) => void; notice: Notice; onNotice: (notice: Notice) => void }) {
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ username: "admin", password: "", setupToken: "" });
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); onNotice(null);
    try {
      const session = await api<Session>("/api/system/initialize", { method: "POST", body: form });
      onReady(session);
    } catch (error) {
      onNotice({ tone: "error", text: error instanceof Error ? error.message : "初始化失败" });
    } finally { setBusy(false); }
  }
  return (
    <AuthFrame eyebrow="首次初始化" title="创建管理员" description="此账户只保存在你的 D1 数据库中。密码至少 12 位。">
      <NoticeBar notice={notice} onClose={() => onNotice(null)} />
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

function LoginPage({ onReady, notice, onNotice }: { onReady: (session: Session) => void; notice: Notice; onNotice: (notice: Notice) => void }) {
  const [busy, setBusy] = useState(false);
  const [form, setForm] = useState({ username: "", password: "" });
  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true); onNotice(null);
    try {
      onReady(await api<Session>("/api/auth/login", { method: "POST", body: form }));
    } catch (error) {
      onNotice({ tone: "error", text: error instanceof Error ? error.message : "登录失败" });
    } finally { setBusy(false); }
  }
  return (
    <AuthFrame eyebrow="管理控制台" title="欢迎回来" description="使用管理员账户继续。会话保存在安全的 HttpOnly Cookie 中。">
      <NoticeBar notice={notice} onClose={() => onNotice(null)} />
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
        <nav aria-label="主导航">{navigation.map((item) => <button key={item.path} className={path.startsWith(item.path) ? "active" : ""} onClick={() => navigate(item.path)}><span>{item.icon}</span>{item.label}</button>)}</nav>
        <div className="sidebar-foot"><div className="avatar">{session.username.slice(0, 1).toUpperCase()}</div><div><strong>{session.username}</strong><small>系统管理员</small></div><button className="icon-button" aria-label="退出登录" onClick={logout}>↪</button></div>
      </aside>
      <main className="content">
        <header className="topbar"><div><p className="eyebrow">CloudSub Console</p><h1>{active.label}</h1></div><div className="edge-state"><span className="pulse" /> SYS: NOMINAL</div></header>
        {children}
      </main>
    </div>
  );
}

function DashboardPage() {
  const state = useAsync(async () => api<{ counts: { sources: number; nodes: number; subscriptions: number }; recentErrors: Array<{ name: string; error: string; created_at: string }>; lastSubscriptionAccess: string | null }>("/api/dashboard"), []);
  const data = state.data;
  const cards = [
    { label: "启用数据源", value: data?.counts.sources ?? "—", note: "持续同步", color: "green", index: "01" },
    { label: "有效节点", value: data?.counts.nodes ?? "—", note: "已标准化", color: "blue", index: "02" },
    { label: "有效订阅", value: data?.counts.subscriptions ?? "—", note: "令牌保护", color: "purple", index: "03" },
  ];
  return <div className="page-grid">
    <section className="hero-card"><div><p className="eyebrow">系统状态</p><h2>你的配置，运行在边缘。</h2><p>从导入、解析到分发，所有数据都留在你的 Cloudflare 账户中。</p></div><div className="orbit"><span>C</span></div></section>
    <section className="stats">{cards.map((card) => <article className="stat-card" key={card.label} data-index={card.index}><span className={"stat-dot " + card.color} /><p>{card.label}</p><strong>{card.value}</strong><small>{card.note}</small></article>)}</section>
    <section className="panel span-two">
      <div className="panel-head"><div><p className="eyebrow">运行摘要</p><h3>最近状态</h3></div><span className="status-pill good">自动刷新已启用</span></div>
      <ListState state={state} empty={<>
        <div className="summary-row"><span>最近订阅访问</span><strong>{formatTime(data?.lastSubscriptionAccess)}</strong></div>
        <div className="summary-row"><span>定时刷新</span><strong>每 30 分钟 · UTC</strong></div>
        <div className="summary-row"><span>最近错误</span><strong>{data?.recentErrors.length ? data.recentErrors.length + " 条" : "无"}</strong></div>
        {data?.recentErrors.map((item) => <div className="error-row" key={item.created_at}><span>{item.name}</span><p>{item.error}</p><time>{formatTime(item.created_at)}</time></div>)}
      </>} />
    </section>
  </div>;
}

// ─── 数据源 ──────────────────────────────────────────────────────────

function SourcesPage() {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const search = useDebounced(query);
  const [busy, run] = useBusy();
  const [notice, setNotice] = useState<Notice>(null);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ name: "", kind: "url" as "url" | "manual" | "standalone", url: "", content: "", refreshInterval: 60 });
  const list = usePagedList<Source>("/api/sources", search ? { q: search } : {}, page, 25);
  useEffect(() => { setPage(1); }, [search]);

  async function create(event: FormEvent) {
    event.preventDefault();
    setNotice(null);
    await run(async () => {
      try {
        const type = form.kind === "url" ? "url" : "manual";
        const sourceKind = form.kind === "standalone" ? "standalone" : "subscription";
        const result = await api<{ refreshError?: string }>("/api/sources", { method: "POST", body: { ...form, type, sourceKind, enabled: true, timeoutMs: 15000 } });
        setNotice({ tone: result.refreshError ? "error" : "success", text: result.refreshError ?? (sourceKind === "standalone" ? "节点已添加" : "数据源已创建并完成解析") });
        setForm({ name: "", kind: "url", url: "", content: "", refreshInterval: 60 });
        setShowForm(false);
        await list.retry();
      } catch (error) {
        setNotice({ tone: "error", text: error instanceof Error ? error.message : "创建失败" });
      }
    });
  }

  async function refresh(id: string) {
    setNotice(null);
    await run(async () => {
      try {
        const result = await api<{ nodeCount: number }>("/api/sources/" + id + "/refresh", { method: "POST" });
        setNotice({ tone: "success", text: "刷新完成，共解析 " + result.nodeCount + " 个节点" });
        await list.retry();
      } catch (error) {
        setNotice({ tone: "error", text: error instanceof Error ? error.message : "刷新失败" });
      }
    });
  }

  async function remove(id: string, name: string) {
    if (!window.confirm("删除数据源“" + name + "”及其节点？所有引用它的订阅会立即失效。此操作无法撤销。")) return;
    setNotice(null);
    await run(async () => {
      try {
        await api("/api/sources/" + id, { method: "DELETE" });
        setNotice({ tone: "success", text: "数据源已删除" });
        await list.retry();
      } catch (error) {
        setNotice({ tone: "error", text: error instanceof Error ? error.message : "删除失败" });
      }
    });
  }

  const items = list.data?.items ?? [];
  return <section className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">Upstream registry</p><h2>数据源</h2><p className="muted">导入你拥有或已获授权的 HTTPS 订阅与手动配置。</p></div><button className="button primary" onClick={() => setShowForm(!showForm)}>{showForm ? "取消" : "+ 添加数据源"}</button></div>
    <NoticeBar notice={notice} onClose={() => setNotice(null)} />
    {showForm && <form className="form-card" onSubmit={create}>
      <div className="form-grid"><label>名称<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="例如：主订阅" required /></label><label>类型<select value={form.kind} onChange={(event) => setForm({ ...form, kind: event.target.value as "url" | "manual" | "standalone" })}><option value="url">订阅链接（HTTPS URL）</option><option value="manual">手动配置</option><option value="standalone">单节点链接</option></select></label></div>
      {form.kind === "url" ? <label>上游地址<input type="url" value={form.url} onChange={(event) => setForm({ ...form, url: event.target.value })} placeholder="https://example.com/subscription" required /></label> : <label>配置内容<textarea rows={form.kind === "standalone" ? 4 : 8} value={form.content} onChange={(event) => setForm({ ...form, content: event.target.value })} placeholder={form.kind === "standalone" ? "粘贴单个节点链接（ss:// vmess:// vless:// trojan:// hysteria2:// tuic:// anytls://）" : "粘贴 Clash YAML、URI 列表或内部 JSON"} required /></label>}
      <div className="form-actions"><label className="compact">刷新周期（分钟）<input type="number" min={5} value={form.refreshInterval} onChange={(event) => setForm({ ...form, refreshInterval: Number(event.target.value) })} /></label><button className="button primary" disabled={busy}>{busy ? "处理中…" : form.kind === "standalone" ? "添加节点" : "保存并解析"}</button></div>
    </form>}
    <div className="filters"><label className="sr-only" htmlFor="source-search">搜索数据源</label><input id="source-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索数据源名称" /></div>
    <div className="table-wrap"><table><thead><tr><th>数据源</th><th>类型</th><th>节点</th><th>最近成功</th><th>状态</th><th /></tr></thead><tbody>
      {items.map((item) => <tr key={item.id}><td><strong>{item.name}</strong><small>{item.type === "url" ? item.url : item.source_kind === "standalone" ? "单节点链接 · 已加密" : "手动内容 · 已加密"}</small></td><td><span className="protocol">{item.source_kind === "standalone" ? "单节点" : "订阅源"}</span></td><td>{item.node_count ?? 0}</td><td>{formatTime(item.last_success_at)}</td><td>{item.last_error ? <span className="status-pill bad" title={item.last_error}>异常</span> : <span className="status-pill good">正常</span>}</td><td className="actions"><button className="button ghost small" disabled={busy} onClick={() => void refresh(item.id)}>刷新</button><button className="button danger small" disabled={busy} onClick={() => void remove(item.id, item.name)}>删除</button></td></tr>)}
    </tbody></table></div>
    <ListState state={list} empty={items.length === 0 ? <div className="empty">还没有数据源。添加第一个上游或手动配置开始。</div> : null} />
    <Pagination page={page} pageSize={25} total={list.data?.total ?? 0} onPage={setPage} label="数据源分页" />
  </section>;
}

// ─── 节点 ────────────────────────────────────────────────────────────

function NodeTable({ items, onToggle, busy }: { items: NodeItem[]; onToggle: (item: NodeItem) => void; busy: boolean }) {
  return <div className="table-wrap"><table><thead><tr><th>名称</th><th>协议</th><th>服务器</th><th>来源</th><th>启用</th></tr></thead><tbody>{items.map((item) => <tr key={item.id}><td><strong>{item.name}</strong>{item.tags.length > 0 && <small>{item.tags.join(" · ")}</small>}</td><td><span className="protocol">{item.protocol}</span></td><td className="mono">{item.server}:{item.port}</td><td>{item.source_name}</td><td><button type="button" className={"switch " + (item.enabled ? "on" : "")} aria-label={item.enabled ? "停用 " + item.name : "启用 " + item.name} aria-pressed={Boolean(item.enabled)} disabled={busy} onClick={() => onToggle(item)}><span /></button></td></tr>)}</tbody></table></div>;
}

function NodeGroup({ title, state, onToggle, busy, page, onPage }: { title: string; state: ReturnType<typeof usePagedList<NodeItem>>; onToggle: (item: NodeItem) => void; busy: boolean; page: number; onPage: (page: number) => void }) {
  const items = state.data?.items ?? [];
  return <div className="node-group">
    <div className="node-group-head"><h3>{title}</h3><span className="status-pill neutral">{state.data?.total ?? 0} 个节点</span></div>
    <ListState state={state} empty={items.length === 0 ? <div className="empty">该分组暂无节点。</div> : null} />
    {items.length > 0 && <NodeTable items={items} onToggle={onToggle} busy={busy} />}
    <Pagination page={page} pageSize={25} total={state.data?.total ?? 0} onPage={onPage} label={title + "分页"} />
  </div>;
}

function NodesPage() {
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("");
  const [subPage, setSubPage] = useState(1);
  const [stdPage, setStdPage] = useState(1);
  const [busy, run] = useBusy();
  const [notice, setNotice] = useState<Notice>(null);
  const search = useDebounced(query);
  // Search/filter changes reset both groups back to page 1 (accurate totals
  // per group are computed server-side).
  useEffect(() => { setSubPage(1); setStdPage(1); }, [search, protocol]);
  const shared = { q: search, protocol };
  const subscriptionNodes = usePagedList<NodeItem>("/api/nodes", { ...shared, sourceKind: "subscription" }, subPage, 25);
  const standaloneNodes = usePagedList<NodeItem>("/api/nodes", { ...shared, sourceKind: "standalone" }, stdPage, 25);

  async function toggle(item: NodeItem) {
    setNotice(null);
    await run(async () => {
      try {
        await api("/api/nodes/" + item.id, { method: "PUT", body: { enabled: !item.enabled } });
        await Promise.all([subscriptionNodes.retry(), standaloneNodes.retry()]);
      } catch (error) {
        setNotice({ tone: "error", text: error instanceof Error ? error.message : "更新失败" });
      }
    });
  }

  return <section className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">Normalized inventory</p><h2>节点</h2><p className="muted">敏感字段默认脱敏；禁用状态会在上游刷新后保留。</p></div><span className="status-pill neutral">{(subscriptionNodes.data?.total ?? 0) + (standaloneNodes.data?.total ?? 0)} 条结果</span></div>
    <NoticeBar notice={notice} onClose={() => setNotice(null)} />
    <div className="filters"><label className="sr-only" htmlFor="node-search">搜索节点名称</label><input id="node-search" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索节点名称" /><label className="sr-only" htmlFor="node-protocol">按协议筛选</label><select id="node-protocol" value={protocol} onChange={(event) => setProtocol(event.target.value)}><option value="">全部协议</option>{PROTOCOLS.map((value) => <option key={value}>{value}</option>)}</select></div>
    <NodeGroup title="订阅节点" state={subscriptionNodes} onToggle={toggle} busy={busy} page={subPage} onPage={setSubPage} />
    <NodeGroup title="单独节点" state={standaloneNodes} onToggle={toggle} busy={busy} page={stdPage} onPage={setStdPage} />
  </section>;
}

// ─── 订阅 ────────────────────────────────────────────────────────────

function SubscriptionForm({ form, setForm, sources, busy, submitLabel, onSubmit }: {
  form: SubscriptionFormState;
  setForm: (form: SubscriptionFormState) => void;
  sources: SourceOption[];
  busy: boolean;
  submitLabel: string;
  onSubmit: (event: FormEvent) => void;
}) {
  const [regexError, setRegexError] = useState<string | null>(null);
  function validateRegex(): boolean {
    const fields: Array<[string, string]> = [
      ["includeName", form.includeName],
      ["excludeName", form.excludeName],
      ...form.rename.filter((rule) => rule.pattern.trim()).map((rule, index) => ["rename[" + index + "]", rule.pattern] as [string, string]),
    ];
    for (const [field, pattern] of fields) {
      const reason = validateSafePattern(pattern.trim());
      if (reason !== null) { setRegexError(field + "：" + reason); return false; }
    }
    setRegexError(null);
    return true;
  }
  function handleSubmit(event: FormEvent) {
    event.preventDefault();
    if (!validateRegex()) return;
    onSubmit(event);
  }
  return <form className="form-card" onSubmit={handleSubmit}>
    <div className="form-grid">
      <label>名称<input value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="例如：日常设备" required /></label>
      <label>默认格式<select value={form.defaultTarget} onChange={(event) => setForm({ ...form, defaultTarget: event.target.value as SubscriptionTarget })}><option value="mihomo">Mihomo YAML</option><option value="singbox">Sing-box JSON</option><option value="raw">Raw Base64</option><option value="json">内部 JSON</option></select></label>
    </div>
    <div className="form-grid">
      <label className="check"><input type="checkbox" checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />启用订阅</label>
      <label>过期时间<input type="datetime-local" value={form.expiresAt} onChange={(event) => setForm({ ...form, expiresAt: event.target.value })} /></label>
    </div>
    <fieldset><legend>包含的数据源</legend><div className="check-grid">{sources.map((source) => <label className="check" key={source.id}><input type="checkbox" checked={form.sourceIds.includes(source.id)} onChange={(event) => setForm({ ...form, sourceIds: event.target.checked ? [...form.sourceIds, source.id] : form.sourceIds.filter((id) => id !== source.id) })} />{source.name}</label>)}</div></fieldset>
    <fieldset><legend>协议过滤</legend><div className="check-grid">{PROTOCOLS.map((value) => <label className="check" key={value}><input type="checkbox" checked={form.protocols.includes(value)} onChange={(event) => setForm({ ...form, protocols: event.target.checked ? [...form.protocols, value] : form.protocols.filter((p) => p !== value) })} />{value}</label>)}</div></fieldset>
    <fieldset><legend>名称过滤（线性时间安全正则，详见 docs/security.md）</legend>
      <div className="form-grid">
        <label>包含匹配<input value={form.includeName} onChange={(event) => setForm({ ...form, includeName: event.target.value })} placeholder="例如：HK|SG|JP" /></label>
        <label>排除匹配<input value={form.excludeName} onChange={(event) => setForm({ ...form, excludeName: event.target.value })} placeholder="例如：^免费|广告" /></label>
      </div>
      <label>排序<select value={form.sortBy} onChange={(event) => setForm({ ...form, sortBy: event.target.value as SubscriptionFormState["sortBy"] })}><option value="name">按名称</option><option value="protocol">按协议</option><option value="source">按来源</option></select></label>
      <div className="rename-list">
        {form.rename.map((rule, index) => <div className="form-grid" key={index}>
          <label>正则<small>（第 {index + 1} 条）</small><input value={rule.pattern} onChange={(event) => setForm({ ...form, rename: form.rename.map((r, i) => i === index ? { ...r, pattern: event.target.value } : r) })} placeholder="例如：Tokyo (\d+)" /></label>
          <label>替换为<input value={rule.replacement} onChange={(event) => setForm({ ...form, rename: form.rename.map((r, i) => i === index ? { ...r, replacement: event.target.value } : r) })} placeholder="例如：JP-$1" /></label>
          <button type="button" className="button danger small" onClick={() => setForm({ ...form, rename: form.rename.filter((_, i) => i !== index) })}>删除</button>
        </div>)}
        {form.rename.length < 20 && <button type="button" className="button ghost small" onClick={() => setForm({ ...form, rename: [...form.rename, { pattern: "", replacement: "" }] })}>+ 添加重命名规则</button>}
      </div>
    </fieldset>
    {regexError && <div className="callout error" role="alert">{regexError}</div>}
    <div className="form-actions"><span className="muted">规则保存后立即生效，并会使缓存输出失效。</span><button className="button primary" disabled={busy || !form.sourceIds.length}>{busy ? "处理中…" : submitLabel}</button></div>
  </form>;
}

function SubscriptionsPage() {
  const [page, setPage] = useState(1);
  const [busy, run] = useBusy();
  const [notice, setNotice] = useState<Notice>(null);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState<SubscriptionDetail | null>(null);
  const [form, setForm] = useState<SubscriptionFormState>(EMPTY_FORM);
  const [token, setToken] = useState<{ subscriptionId: string; url: string } | null>(null);
  const [copyResult, setCopyResult] = useState<boolean | null>(null);
  const [preview, setPreview] = useState<{ body: string; nodeCount: number; error: string | null } | null>(null);

  const list = usePagedList<Subscription>("/api/subscriptions", {}, page, 25);
  const options = useAsync(async () => api<{ items: SourceOption[] }>("/api/sources/options").then((data) => data.items), []);

  function resetForm() { setForm(EMPTY_FORM); setEditing(null); setShowForm(false); }

  async function submit(event: FormEvent) {
    event.preventDefault();
    setNotice(null);
    await run(async () => {
      try {
        const payload = {
          name: form.name,
          sourceIds: form.sourceIds,
          enabled: form.enabled,
          defaultTarget: form.defaultTarget,
          expiresAt: form.expiresAt ? new Date(form.expiresAt).toISOString() : null,
          cacheTtl: 300,
          rules: {
            protocols: form.protocols.length ? form.protocols : undefined,
            includeName: form.includeName.trim() || undefined,
            excludeName: form.excludeName.trim() || undefined,
            sortBy: form.sortBy,
            rename: form.rename.filter((rule) => rule.pattern.trim()).map((rule) => ({ pattern: rule.pattern.trim(), replacement: rule.replacement })),
          },
        };
        if (editing) {
          await api("/api/subscriptions/" + editing.id, { method: "PUT", body: payload });
          setNotice({ tone: "success", text: "订阅已更新" });
        } else {
          const result = await api<{ id: string; token: string }>("/api/subscriptions", { method: "POST", body: payload });
          setToken({ subscriptionId: result.id, url: window.location.origin + "/sub/" + result.token });
          setNotice({ tone: "success", text: "订阅已创建。完整令牌只显示这一次。" });
        }
        resetForm();
        await list.retry();
      } catch (error) {
        if (error instanceof ApiError && error.details) {
          const first = Object.values(error.details as Record<string, unknown>).flat().find((value) => typeof value === "string");
          setNotice({ tone: "error", text: typeof first === "string" ? first : error.message });
        } else {
          setNotice({ tone: "error", text: error instanceof Error ? error.message : "保存失败" });
        }
      }
    });
  }

  async function openEdit(item: Subscription) {
    setNotice(null);
    await run(async () => {
      try {
        const detail = await api<SubscriptionDetail>("/api/subscriptions/" + item.id);
        setForm({
          name: detail.name,
          sourceIds: detail.sourceIds,
          enabled: Boolean(detail.enabled),
          expiresAt: detail.expires_at ? detail.expires_at.slice(0, 16) : "",
          defaultTarget: detail.default_target as SubscriptionTarget,
          protocols: detail.rules.protocols ?? [],
          includeName: detail.rules.includeName ?? "",
          excludeName: detail.rules.excludeName ?? "",
          sortBy: detail.rules.sortBy ?? "name",
          rename: detail.rules.rename ?? [],
        });
        setEditing(detail);
        setShowForm(true);
      } catch (error) {
        setNotice({ tone: "error", text: error instanceof Error ? error.message : "加载订阅失败" });
      }
    });
  }

  async function rotate(item: Subscription) {
    if (!window.confirm("旧订阅地址将立即失效，继续轮换令牌？")) return;
    setNotice(null);
    await run(async () => {
      try {
        const result = await api<{ token: string }>("/api/subscriptions/" + item.id + "/rotate-token", { method: "POST" });
        setToken({ subscriptionId: item.id, url: window.location.origin + "/sub/" + result.token });
        setCopyResult(null);
        setNotice({ tone: "success", text: "令牌已轮换，请立即保存新地址。" });
        await list.retry();
      } catch (error) {
        setNotice({ tone: "error", text: error instanceof Error ? error.message : "轮换失败" });
      }
    });
  }

  async function remove(item: Subscription) {
    if (!window.confirm("删除订阅“" + item.name + "”？其所有令牌将立即失效，此操作无法撤销。")) return;
    setNotice(null);
    await run(async () => {
      try {
        await api("/api/subscriptions/" + item.id, { method: "DELETE" });
        // Never leave a one-time token on screen for a deleted subscription.
        if (token?.subscriptionId === item.id) setToken(null);
        setNotice({ tone: "success", text: "订阅已删除，关联令牌已失效" });
        await list.retry();
      } catch (error) {
        setNotice({ tone: "error", text: error instanceof Error ? error.message : "删除失败" });
      }
    });
  }

  async function showPreview(item: Subscription) {
    setNotice(null);
    await run(async () => {
      try {
        const result = await api<{ body: string; nodeCount: number }>("/api/subscriptions/" + item.id + "/preview", { method: "POST", body: { target: item.default_target } });
        setPreview({ body: result.body, nodeCount: result.nodeCount, error: null });
      } catch (error) {
        setPreview({ body: "", nodeCount: 0, error: error instanceof Error ? error.message : "预览失败" });
      }
    });
  }

  async function copyTokenUrl() {
    if (!token) return;
    const copied = await copyText(token.url);
    setCopyResult(copied);
    setNotice({ tone: copied ? "success" : "error", text: copied ? "订阅地址已复制" : "复制失败，请点击地址框手动复制" });
  }

  const items = list.data?.items ?? [];
  return <section className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">Tokenized delivery</p><h2>订阅</h2><p className="muted">组合多个数据源，通过不可猜测令牌安全分发。</p></div><button className="button primary" onClick={() => { resetForm(); setShowForm(!showForm); }}>{showForm ? "取消" : "+ 创建订阅"}</button></div>
    <NoticeBar notice={notice} onClose={() => setNotice(null)} />
    {token && <TokenReveal url={token.url} onCopy={() => void copyTokenUrl()} copyResult={copyResult} busy={busy} />}
    {showForm && <SubscriptionForm form={form} setForm={setForm} sources={options.data ?? []} busy={busy} submitLabel={editing ? "保存修改" : "创建并生成令牌"} onSubmit={submit} />}
    <div className="card-list">{items.map((item) => <article className="subscription-card" key={item.id}><div className="sub-icon">⌁</div><div className="sub-copy"><div><h3>{item.name}</h3><span className={"status-pill " + (item.enabled ? "good" : "neutral")}>{item.enabled ? "运行中" : "已暂停"}</span></div><p><span className="protocol">{item.default_target}</span> · {item.sourceIds.length} 个数据源 · 令牌 {item.token_prefix ?? "—"}••••</p><small>最近访问：{formatTime(item.last_access_at)}</small></div><div className="actions"><button className="button ghost small" disabled={busy} onClick={() => void openEdit(item)}>编辑</button><button className="button ghost small" disabled={busy} onClick={() => void showPreview(item)}>预览</button><button className="button ghost small" disabled={busy} onClick={() => void rotate(item)}>轮换令牌</button><button className="button danger small" disabled={busy} onClick={() => void remove(item)}>删除</button></div></article>)}</div>
    <ListState state={list} empty={items.length === 0 ? <div className="empty">还没有订阅。选择数据源后创建第一条。</div> : null} />
    <Pagination page={page} pageSize={25} total={list.data?.total ?? 0} onPage={setPage} label="订阅分页" />
    {preview && <Modal title={preview.error ? "预览失败" : preview.nodeCount + " 个节点"} eyebrow="输出预览" onClose={() => setPreview(null)}>{preview.error ? <div className="callout error" role="alert">{preview.error}</div> : <pre>{preview.body}</pre>}</Modal>}
  </section>;
}

// ─── 日志与设置 ──────────────────────────────────────────────────────

interface AuditEntry {
  id: string;
  action: string;
  target_type: string;
  username: string;
  created_at: string;
  request_id: string;
}

function LogsPage() {
  const [page, setPage] = useState(1);
  const list = usePagedList<AuditEntry>("/api/audit-logs", {}, page, 25);
  const items = list.data?.items ?? [];
  return <section className="panel page-panel">
    <div className="panel-head"><div><p className="eyebrow">Audit trail</p><h2>审计日志</h2><p className="muted">所有管理修改都会记录动作、目标和请求 ID。</p></div><span className="status-pill neutral">{list.data?.total ?? 0} 条</span></div>
    <ListState state={list} empty={items.length === 0 ? <div className="empty">暂无审计记录。</div> : null} />
    <div className="timeline">{items.map((item) => <div className="timeline-item" key={item.id}><span className="timeline-dot" /><div><strong>{item.action}</strong><p>{item.username ?? "system"} · {item.target_type ?? "system"}</p><small>{formatTime(item.created_at)} · {item.request_id?.slice(0, 8)}</small></div></div>)}</div>
    <Pagination page={page} pageSize={25} total={list.data?.total ?? 0} onPage={setPage} label="审计日志分页" />
  </section>;
}

function SettingsPage() {
  const [timezone, setTimezone] = useState("UTC");
  const [limits, setLimits] = useState<{ maxSourceBytes: number; sessionTtl: number; subscriptionCacheTtl: number }>();
  const [password, setPassword] = useState({ currentPassword: "", newPassword: "" });
  const [notice, setNotice] = useState<Notice>(null);
  const [busy, run] = useBusy();
  const settings = useAsync(async () => api<{ timezone?: string; limits: typeof limits }>("/api/settings"), []);
  useEffect(() => { if (settings.data) { setTimezone(settings.data.timezone ?? "UTC"); setLimits(settings.data.limits); } }, [settings.data]);
  async function save(event: FormEvent) {
    event.preventDefault();
    setNotice(null);
    await run(async () => {
      try { await api("/api/settings", { method: "PUT", body: { timezone } }); setNotice({ tone: "success", text: "系统设置已保存" }); }
      catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "保存失败" }); }
    });
  }
  async function changePassword(event: FormEvent) {
    event.preventDefault();
    setNotice(null);
    await run(async () => {
      try {
        await api("/api/auth/password", { method: "PUT", body: password });
        setPassword({ currentPassword: "", newPassword: "" });
        setNotice({ tone: "success", text: "密码已修改，其他会话已退出" });
      } catch (error) { setNotice({ tone: "error", text: error instanceof Error ? error.message : "修改失败" }); }
    });
  }
  return <div className="settings-grid"><NoticeBar notice={notice} onClose={() => setNotice(null)} /><section className="panel"><div className="panel-head"><div><p className="eyebrow">Preferences</p><h2>系统设置</h2></div></div><ListState state={settings} empty={null} /><form className="stack" onSubmit={save}><label>显示时区<input value={timezone} onChange={(event) => setTimezone(event.target.value)} placeholder="Asia/Shanghai" /></label><div className="setting-facts"><div><span>上游大小限制</span><strong>{limits ? Math.round(limits.maxSourceBytes / 1024 / 1024) + " MB" : "—"}</strong></div><div><span>订阅缓存</span><strong>{limits?.subscriptionCacheTtl ?? "—"} 秒</strong></div><div><span>会话有效期</span><strong>{limits ? Math.round(limits.sessionTtl / 86400) + " 天" : "—"}</strong></div></div><button className="button primary" disabled={busy}>{busy ? "保存中…" : "保存设置"}</button></form></section><section className="panel"><div className="panel-head"><div><p className="eyebrow">Security</p><h2>修改密码</h2></div></div><form className="stack" onSubmit={changePassword}><label>当前密码<input type="password" value={password.currentPassword} onChange={(event) => setPassword({ ...password, currentPassword: event.target.value })} required /></label><label>新密码<input type="password" minLength={12} value={password.newPassword} onChange={(event) => setPassword({ ...password, newPassword: event.target.value })} required /></label><button className="button ghost" disabled={busy}>{busy ? "更新中…" : "更新密码"}</button></form></section></div>;
}

// ─── 根组件 ──────────────────────────────────────────────────────────

export default function App() {
  const [status, setStatus] = useState<SystemStatus>();
  const [session, setSession] = useState<Session>();
  const [path, setPath] = useState(window.location.pathname);
  const [boot, setBoot] = useState<{ loading: boolean; error: string | null }>({ loading: true, error: null });
  const [bootTick, setBootTick] = useState(0);
  const [notice, setNotice] = useState<Notice>(null);

  useEffect(() => {
    const listener = () => setPath(window.location.pathname);
    window.addEventListener("popstate", listener);
    return () => window.removeEventListener("popstate", listener);
  }, []);

  // Bootstrap: status + session. Errors surface with a retry instead of an
  // endless spinner.
  useEffect(() => {
    let cancelled = false;
    setBoot({ loading: true, error: null });
    void (async () => {
      try {
        const system = await api<SystemStatus>("/api/system/status");
        if (cancelled) return;
        setStatus(system);
        if (system.initialized) {
          try {
            const current = await api<Session>("/api/auth/session");
            if (!cancelled) setSession(current);
          } catch (error) {
            if (!(error instanceof ApiError) || error.code !== "authentication_required") console.warn(error);
          }
        }
      } catch (error) {
        if (!cancelled) setBoot({ loading: false, error: error instanceof Error ? error.message : "无法连接服务器" });
      } finally {
        if (!cancelled) setBoot((previous) => ({ ...previous, loading: false }));
      }
    })();
    return () => { cancelled = true; };
  }, [bootTick]);

  // Session expiry: notify and redirect to login.
  useEffect(() => onSessionExpired(() => {
    setSession(undefined);
    setNotice({ tone: "error", text: "会话已过期，请重新登录" });
    navigate("/login");
  }), []);

  function navigate(next: string) { window.history.pushState({}, "", next); setPath(next); }
  async function logout() { try { await api("/api/auth/logout", { method: "POST" }); } finally { setSession(undefined); navigate("/login"); } }

  if (boot.loading || !status) {
    return <div className="loading-screen"><Logo /><div className="loader" /><p className="muted">正在连接边缘网络…</p></div>;
  }
  if (boot.error) {
    return (
      <div className="loading-screen"><Logo /><div className="callout error" role="alert">{boot.error}</div><button className="button primary" onClick={() => setBootTick((value) => value + 1)}>重试</button></div>
    );
  }
  if (!status.initialized) {
    return <SetupPage status={status} notice={notice} onNotice={setNotice} onReady={(value) => { setSession(value); setStatus({ ...status, initialized: true }); navigate("/dashboard"); }} />;
  }
  if (!session) {
    return <LoginPage notice={notice} onNotice={setNotice} onReady={(value) => { setSession(value); setNotice(null); navigate("/dashboard"); }} />;
  }
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
