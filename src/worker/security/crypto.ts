const encoder = new TextEncoder();
const decoder = new TextDecoder();

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export function base64UrlToBytes(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function randomToken(byteLength = 32): string {
  return bytesToBase64Url(crypto.getRandomValues(new Uint8Array(byteLength)));
}

export async function sha256Bytes(value: string | Uint8Array): Promise<Uint8Array> {
  const input = typeof value === "string" ? encoder.encode(value) : value;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", arrayBuffer(input)));
}

export async function sha256Hex(value: string | Uint8Array): Promise<string> {
  const digest = await sha256Bytes(value);
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function hmacSha256Hex(secret: string, value: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    arrayBuffer(encoder.encode(secret)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, arrayBuffer(encoder.encode(value))));
  return [...signature].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function constantTimeEqual(left: string, right: string): boolean {
  const a = encoder.encode(left);
  const b = encoder.encode(right);
  let difference = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    difference |= (a[index] ?? 0) ^ (b[index] ?? 0);
  }
  return difference === 0;
}

async function encryptionKey(secret: string): Promise<CryptoKey> {
  const keyBytes = await sha256Bytes(secret);
  return crypto.subtle.importKey("raw", arrayBuffer(keyBytes), "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function encryptJson(value: unknown, secret: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: arrayBuffer(iv) },
    await encryptionKey(secret),
    encoder.encode(JSON.stringify(value)),
  );
  return ["v1", bytesToBase64Url(iv), bytesToBase64Url(new Uint8Array(ciphertext))].join(".");
}

export async function decryptJson<T>(value: string, secret: string): Promise<T> {
  const [version, iv, ciphertext] = value.split(".");
  if (version !== "v1" || !iv || !ciphertext) throw new Error("Unsupported encrypted payload");
  const plaintext = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: arrayBuffer(base64UrlToBytes(iv)) },
    await encryptionKey(secret),
    arrayBuffer(base64UrlToBytes(ciphertext)),
  );
  return JSON.parse(decoder.decode(plaintext)) as T;
}
