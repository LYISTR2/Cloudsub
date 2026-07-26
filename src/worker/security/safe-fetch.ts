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

/**
 * Canonicalise an IPv4 host into four octets, understanding the historical
 * `inet_aton` encodings that attackers use to smuggle private targets past
 * naive dotted-quad checks: decimal integers (`2130706433`), hex
 * (`0x7f000001`), octal (`0177.0.0.1`), and short forms (`127.1`).
 * Returns undefined when the host is not an IPv4 literal in any of these
 * forms (e.g. a normal domain name).
 */
export function canonicalizeIpv4(hostname: string): [number, number, number, number] | undefined {
  const parts = hostname.split(".");
  if (parts.length < 1 || parts.length > 4) return undefined;
  const numbers: number[] = [];
  for (const part of parts) {
    let value: number;
    if (/^0x[0-9a-f]+$/iu.test(part)) value = Number.parseInt(part.slice(2), 16);
    else if (/^0[0-7]+$/u.test(part)) value = Number.parseInt(part, 8);
    else if (/^(0|[1-9][0-9]*)$/u.test(part)) value = Number.parseInt(part, 10);
    else return undefined;
    if (!Number.isInteger(value) || value < 0) return undefined;
    numbers.push(value);
  }
  const octets: [number, number, number, number] = [0, 0, 0, 0];
  const leading = numbers.slice(0, -1);
  for (let index = 0; index < leading.length; index += 1) {
    if (leading[index] > 255) return undefined;
    octets[index] = leading[index];
  }
  const remaining = 4 - leading.length;
  const last = numbers[numbers.length - 1];
  if (last > (remaining >= 4 ? 0xff_ff_ff_ff : 256 ** remaining - 1)) return undefined;
  for (let index = 0; index < remaining; index += 1) {
    octets[3 - index] = Math.floor(last / 256 ** index) % 256;
  }
  return octets;
}

function isBlockedIpv4(hostname: string): boolean {
  const octets = canonicalizeIpv4(hostname);
  if (!octets) return false;
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

/** Expand an IPv6 literal (with optional `::` and embedded IPv4) to 8 hextets. */
function expandIpv6(value: string): number[] | undefined {
  if (!value.includes(":") || value.includes(":::")) return undefined;
  // Fold a trailing dotted-decimal IPv4 (e.g. ::ffff:127.0.0.1) into two hextets.
  let text = value;
  const lastColon = value.lastIndexOf(":");
  const tail = value.slice(lastColon + 1);
  if (tail.includes(".")) {
    const octets = canonicalizeIpv4(tail);
    if (!octets) return undefined;
    text = value.slice(0, lastColon + 1) + ((octets[0] << 8) | octets[1]).toString(16) + ":" + ((octets[2] << 8) | octets[3]).toString(16);
  }
  const halves = text.split("::");
  if (halves.length > 2) return undefined;
  const parseGroups = (part: string): number[] | undefined => {
    if (part === "") return [];
    const groups: number[] = [];
    for (const group of part.split(":")) {
      if (!/^[0-9a-f]{1,4}$/u.test(group)) return undefined;
      groups.push(Number.parseInt(group, 16));
    }
    return groups;
  };
  const left = parseGroups(halves[0]);
  const right = halves.length === 2 ? parseGroups(halves[1]) : [];
  if (!left || !right) return undefined;
  const missing = 8 - left.length - right.length;
  const groups = halves.length === 2 ? (missing < 0 ? undefined : [...left, ...Array(missing).fill(0), ...right]) : left;
  return groups && groups.length === 8 ? groups : undefined;
}

/** Extract the embedded IPv4 from mapped / compatible / NAT64 IPv6 forms. */
function embeddedIpv4(groups: number[]): string | undefined {
  const [g0, g1, g2, g3, g4, g5, g6, g7] = groups;
  const highZero = g0 === 0 && g1 === 0 && g2 === 0 && g3 === 0 && g4 === 0;
  const mapped = highZero && (g5 === 0xffff || g5 === 0); // ::ffff:a.b.c.d / ::a.b.c.d
  const nat64 = g0 === 0x0064 && g1 === 0xff9b && g2 === 0 && g3 === 0 && g4 === 0 && g5 === 0; // 64:ff9b::/96
  if (!mapped && !nat64) return undefined;
  return (g6 >> 8) + "." + (g6 & 0xff) + "." + (g7 >> 8) + "." + (g7 & 0xff);
}

function isBlockedIpv6(hostname: string): boolean {
  const value = hostname.replace(/^\[|\]$/gu, "").toLowerCase();
  if (!value.includes(":")) return false;
  // Conservative string-prefix checks (unchanged from the original filter).
  if (value === "::" || value === "::1" || /^fe[89a-f]/u.test(value) || value.startsWith("ff")) return true;
  if (value.startsWith("fc") || value.startsWith("fd")) return true;
  // Full expansion catches IPv4-mapped / -compatible / NAT64 forms that the URL
  // parser compresses to hex (e.g. ::ffff:7f00:1, which is 127.0.0.1).
  const groups = expandIpv6(value);
  if (!groups) return false;
  const embedded = embeddedIpv4(groups);
  return embedded ? isBlockedIpv4(embedded) : false;
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
