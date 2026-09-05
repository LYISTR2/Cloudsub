import { useCallback, useEffect, useRef, useState } from "react";
import type { DependencyList } from "react";
import { api } from "./api";

export interface AsyncState<T> {
  loading: boolean;
  error: string | null;
  data: T | undefined;
  retry: () => void;
}

/**
 * Loader hook with loading/error/data/retry and stale-response protection:
 * when the loader is re-run (new deps or retry), the previous in-flight
 * promise's resolution is discarded via the `cancelled` signal, so an
 * out-of-order response can never clobber the current one.
 */
export function useAsync<T>(loader: (isCancelled: () => boolean) => Promise<T>, deps: DependencyList): AsyncState<T> {
  const [state, setState] = useState<{ loading: boolean; error: string | null; data: T | undefined }>({ loading: true, error: null, data: undefined });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    let cancelled = false;
    setState((previous) => ({ ...previous, loading: true, error: null }));
    loader(() => cancelled).then(
      (data) => { if (!cancelled) setState({ loading: false, error: null, data }); },
      (error) => {
        if (!cancelled) setState({ loading: false, error: error instanceof Error ? error.message : "加载失败", data: undefined });
      },
    );
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);
  const retry = useCallback(() => setTick((value) => value + 1), []);
  return { ...state, retry };
}

export interface Paged<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
}

/**
 * Paged list loader bound to a page/pageSize state; returns the async state
 * plus a setPage helper. Used by every list view so totals stay accurate.
 */
export function usePagedList<T>(path: string, query: Record<string, string>, page: number, pageSize: number): AsyncState<Paged<T>> & { setPage: (page: number) => void } {
  const [currentPage, setCurrentPage] = useState(page);
  useEffect(() => { setCurrentPage(page); }, [page]);
  const params = new URLSearchParams({ ...query, page: String(currentPage), pageSize: String(pageSize) });
  const state = useAsync<Paged<T>>(
    async () => {
      const result = await api<Paged<T>>(path + "?" + params.toString());
      return { items: result.items ?? [], total: result.total ?? 0, page: result.page ?? currentPage, pageSize: result.pageSize ?? pageSize };
    },
    [path, params.toString()],
  );
  return { ...state, setPage: setCurrentPage };
}

/**
 * Per-component action busy guard: prevents duplicate mutations while an
 * async action is in flight.
 */
export function useBusy(): [boolean, <R>(action: () => Promise<R>) => Promise<R | undefined>] {
  const [busy, setBusy] = useState(false);
  const busyRef = useRef(false);
  const run = useCallback(async <R,>(action: () => Promise<R>): Promise<R | undefined> => {
    // State updates are asynchronous; the ref closes the same-render double
    // click window before React has had a chance to disable the button.
    if (busyRef.current) return undefined;
    busyRef.current = true;
    setBusy(true);
    try {
      return await action();
    } finally {
      busyRef.current = false;
      setBusy(false);
    }
  }, []);
  return [busy, run];
}

/** Debounced value (e.g. for search inputs). */
export function useDebounced<T>(value: T, delayMs = 250): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delayMs);
    return () => clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}

export function formatTime(value: string | null | undefined): string {
  if (!value) return "尚无记录";
  return new Intl.DateTimeFormat("zh-CN", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

/**
 * Scroll-to-top + escape handling for modals.
 */
export function useModalDismiss(onClose: () => void): void {
  const onCloseRef = useRef(onClose);
  useEffect(() => {
    onCloseRef.current = onClose;
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") onCloseRef.current(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
}
