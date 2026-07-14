import { AppError } from "../shared/errors";

const BLOCKED_HOSTS = new Set(["localhost", "localhost.localdomain", "metadata.google.internal"]);
const BLOCKED_HEADERS = new Set([
  "cookie",
  "host",
  "connection",
  "proxy-authorization",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-real-ip",
]);

function isBlockedIpv4(hostname: string): boolean {
  const parts = hostname.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/u.test(part))) return false;
  const octets = parts.map(Number);
  if (octets.some((octet) => octet < 0 || octet > 255)) return true;
  const [a, b] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isBlockedIpv6(hostname: string): boolean {
  const value = hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (!value.includes(":")) return false;
  if (value === "::" || value === "::1" || /^fe[89a-f]/u.test(value) || value.startsWith("ff")) return true;
  if (value.startsWith("fc") || value.startsWith("fd")) return true;
  if (value.startsWith("::ffff:")) return isBlockedIpv4(value.slice(7));
  return false;
}

export function validateUpstreamUrl(input: string): URL {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new AppError(422, "上游地址无效", "invalid_upstream_url");
  }
  const hostname = url.hostname.toLowerCase().replace(/\.$/u, "");
  if (url.protocol !== "https:") throw new AppError(422, "上游地址必须使用 HTTPS", "https_required");
  if (url.username || url.password) throw new AppError(422, "上游地址不能包含用户名或密码", "url_credentials_forbidden");
  if (BLOCKED_HOSTS.has(hostname) || hostname.endsWith(".localhost") || hostname.endsWith(".internal") || hostname.endsWith(".local") || hostname.endsWith(".home.arpa")) {
    throw new AppError(422, "禁止访问本地或内部地址", "private_address");
  }
  if (isBlockedIpv4(hostname) || isBlockedIpv6(hostname)) {
    throw new AppError(422, "禁止访问私有、链路本地或保留地址", "private_address");
  }
  return url;
}

function sanitizedHeaders(input: Record<string, string> | undefined, userAgent: string | undefined): Headers {
  const headers = new Headers({ Accept: "text/plain, application/yaml, application/json;q=0.9, */*;q=0.5" });
  for (const [name, value] of Object.entries(input ?? {})) {
    const normalized = name.toLowerCase();
    if (BLOCKED_HEADERS.has(normalized) || normalized.startsWith("cf-") || normalized.startsWith("sec-")) continue;
    if (/^[\t\x20-\x7e\x80-\xff]*$/u.test(value)) headers.set(name, value);
  }
  if (userAgent) headers.set("User-Agent", userAgent);
  return headers;
}

async function readLimitedBody(response: Response, maxBytes: number): Promise<{ text: string; bytes: number }> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) throw new AppError(413, "上游响应超过大小限制", "source_too_large");
  if (!response.body) return { text: "", bytes: 0 };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > maxBytes) {
      await reader.cancel();
      throw new AppError(413, "上游响应超过大小限制", "source_too_large");
    }
    chunks.push(value);
  }
  const combined = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: new TextDecoder().decode(combined), bytes };
}

export async function safeFetchText(options: {
  url: string;
  headers?: Record<string, string>;
  userAgent?: string;
  timeoutMs: number;
  maxBytes: number;
  maxRedirects?: number;
}): Promise<{ text: string; bytes: number; finalUrl: string }> {
  let url = validateUpstreamUrl(options.url);
  const maxRedirects = options.maxRedirects ?? 3;
  for (let redirect = 0; redirect <= maxRedirects; redirect += 1) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort("timeout"), options.timeoutMs);
    let response: Response;
    try {
      response = await fetch(url, {
        method: "GET",
        headers: sanitizedHeaders(options.headers, options.userAgent),
        redirect: "manual",
        signal: controller.signal,
      });
    } catch (error) {
      throw new AppError(502, error instanceof Error && error.name === "AbortError" ? "上游请求超时" : "无法连接上游", "upstream_fetch_failed");
    } finally {
      clearTimeout(timeout);
    }
    if ([301, 302, 303, 307, 308].includes(response.status)) {
      const location = response.headers.get("location");
      if (!location || redirect === maxRedirects) throw new AppError(502, "上游重定向次数过多", "too_many_redirects");
      url = validateUpstreamUrl(new URL(location, url).toString());
      continue;
    }
    if (!response.ok) throw new AppError(502, "上游返回 HTTP " + response.status, "upstream_http_error");
    const body = await readLimitedBody(response, options.maxBytes);
    return { ...body, finalUrl: url.toString() };
  }
  throw new AppError(502, "上游请求失败", "upstream_fetch_failed");
}
