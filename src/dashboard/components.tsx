import type { ReactNode } from "react";
import type { AsyncState } from "./hooks";
import { useModalDismiss } from "./hooks";

export type Notice = { tone: "success" | "error"; text: string } | null;

export function NoticeBar({ notice, onClose }: { notice: Notice; onClose: () => void }) {
  if (!notice) return null;
  return (
    <div role="status" className={"notice " + notice.tone}>
      <span>{notice.text}</span>
      <button aria-label="关闭提示" onClick={onClose}>×</button>
    </div>
  );
}

export function Pagination({ page, pageSize, total, onPage, label = "分页" }: { page: number; pageSize: number; total: number; onPage: (page: number) => void; label?: string }) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  if (pages <= 1) return null;
  return (
    <nav className="pagination" aria-label={label}>
      <button type="button" className="button ghost small" disabled={page <= 1} onClick={() => onPage(page - 1)}>‹ 上一页</button>
      <span role="status">第 {page} / {pages} 页 · 共 {total} 条</span>
      <button type="button" className="button ghost small" disabled={page >= pages} onClick={() => onPage(page + 1)}>下一页 ›</button>
    </nav>
  );
}

export function ListState({ state, empty }: { state: AsyncState<unknown>; empty: ReactNode }) {
  if (state.loading && state.data === undefined) {
    return <div className="empty"><span className="loader-inline" aria-label="加载中" /> 加载中…</div>;
  }
  if (state.error) {
    return (
      <div className="empty error-empty" role="alert">
        <p>{state.error}</p>
        <button type="button" className="button ghost small" onClick={state.retry}>重试</button>
      </div>
    );
  }
  return <>{empty}</>;
}

export function Modal({ title, eyebrow, onClose, children }: { title: ReactNode; eyebrow?: string; onClose: () => void; children: ReactNode }) {
  useModalDismiss(onClose);
  return (
    <div className="modal-backdrop" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={typeof title === "string" ? title : undefined} onClick={(event) => event.stopPropagation()}>
        <div className="panel-head">
          <div>{eyebrow && <p className="eyebrow">{eyebrow}</p>}<h3>{title}</h3></div>
          <button type="button" className="icon-button" aria-label="关闭" onClick={onClose}>×</button>
        </div>
        {children}
      </div>
    </div>
  );
}

/**
 * One-time token reveal: a read-only, fully selectable URL input so manual
 * copy works even when the clipboard API is unavailable.
 */
export function TokenReveal({ url, onCopy, copyResult, busy }: { url: string; onCopy: () => void; copyResult: boolean | null; busy: boolean }) {
  return (
    <div className="token-reveal">
      <div className="token-reveal-copy">
        <p className="eyebrow">仅显示一次 — 请立即保存</p>
        <input
          id="token-url"
          readOnly
          value={url}
          aria-label="订阅地址（只读，点击全选）"
          onFocus={(event) => event.currentTarget.select()}
          onClick={(event) => event.currentTarget.select()}
        />
        {copyResult === false && <p className="muted">浏览器不支持自动复制，请点击地址框手动复制。</p>}
      </div>
      <button type="button" className="button primary" disabled={busy} onClick={onCopy}>{busy ? "复制中…" : "复制地址"}</button>
    </div>
  );
}
