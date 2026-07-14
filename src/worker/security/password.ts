import { base64UrlToBytes, bytesToBase64Url, constantTimeEqual } from "./crypto";

const encoder = new TextEncoder();
const ITERATIONS = 210_000;

function arrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

async function derive(password: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: arrayBuffer(salt), iterations },
    material,
    256,
  );
  return new Uint8Array(bits);
}

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await derive(password, salt, ITERATIONS);
  return ["pbkdf2_sha256", String(ITERATIONS), bytesToBase64Url(salt), bytesToBase64Url(hash)].join("$");
}

export async function verifyPassword(password: string, encoded: string): Promise<boolean> {
  const [algorithm, iterationValue, saltValue, expected] = encoded.split("$");
  const iterations = Number(iterationValue);
  if (algorithm !== "pbkdf2_sha256" || !Number.isSafeInteger(iterations) || !saltValue || !expected) return false;
  const actual = bytesToBase64Url(await derive(password, base64UrlToBytes(saltValue), iterations));
  return constantTimeEqual(actual, expected);
}
