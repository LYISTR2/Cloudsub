export class ApiError extends Error {
  constructor(message: string, public readonly code = "request_failed", public readonly details?: unknown) {
    super(message);
  }
}

/** Fired once when the API returns 401 (expired/invalid session). */
export const SESSION_EXPIRED_EVENT = "cloudsub:session-expired";

function csrfCookie(): string | undefined {
  const entry = document.cookie.split("; ").find((value) => value.startsWith("cloudsub_csrf="));
  return entry ? decodeURIComponent(entry.slice(entry.indexOf("=") + 1)) : undefined;
}

export function onSessionExpired(handler: () => void): () => void {
  const listener = () => handler();
  window.addEventListener(SESSION_EXPIRED_EVENT, listener);
  return () => window.removeEventListener(SESSION_EXPIRED_EVENT, listener);
}

export async function api<T>(path: string, options: { method?: string; body?: unknown } = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers = new Headers({ Accept: "application/json" });
  if (options.body !== undefined) headers.set("content-type", "application/json");
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = csrfCookie();
    if (csrf) headers.set("x-csrf-token", csrf);
  }
  const response = await fetch(path, {
    method,
    credentials: "same-origin",
    headers,
    body: options.body === undefined ? undefined : JSON.stringify(options.body),
  });
  const payload = await response.json().catch(() => ({})) as { data?: T; error?: { message?: string; code?: string; details?: unknown } };
  if (!response.ok) {
    if (response.status === 401) window.dispatchEvent(new Event(SESSION_EXPIRED_EVENT));
    throw new ApiError(payload.error?.message ?? "请求失败", payload.error?.code, payload.error?.details);
  }
  return payload.data as T;
}
