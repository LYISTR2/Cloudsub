import { describe, expect, it } from "vitest";
import { decryptJson, encryptJson, hmacSha256Hex, sha256Hex } from "../../src/worker/security/crypto";
import { hashPassword, verifyPassword } from "../../src/worker/security/password";
import { validateUpstreamUrl } from "../../src/worker/security/safe-fetch";

describe("security primitives", () => {
  it("hashes passwords with a random PBKDF2 salt", async () => {
    const first = await hashPassword("correct horse battery staple");
    const second = await hashPassword("correct horse battery staple");
    expect(first).not.toBe(second);
    expect(await verifyPassword("correct horse battery staple", first)).toBe(true);
    expect(await verifyPassword("wrong password", first)).toBe(false);
  });

  it("encrypts source secrets with authenticated encryption", async () => {
    const encrypted = await encryptJson({ token: "private" }, "test-encryption-key");
    expect(encrypted).not.toContain("private");
    await expect(decryptJson(encrypted, "wrong-key")).rejects.toThrow();
    expect(await decryptJson(encrypted, "test-encryption-key")).toEqual({ token: "private" });
  });

  it("produces deterministic SHA-256 fingerprints", async () => {
    expect(await sha256Hex("cloudsub")).toHaveLength(64);
    expect(await sha256Hex("cloudsub")).toBe(await sha256Hex("cloudsub"));
  });

  it("keys opaque token indexes with the application secret", async () => {
    expect(await hmacSha256Hex("secret-a", "token")).not.toBe(await hmacSha256Hex("secret-b", "token"));
    expect(await hmacSha256Hex("secret-a", "token")).toHaveLength(64);
  });

  it("allows HTTPS public hosts and rejects local network targets", () => {
    expect(validateUpstreamUrl("https://example.com/sub").hostname).toBe("example.com");
    for (const value of ["http://example.com", "https://localhost/sub", "https://127.0.0.1/sub", "https://192.168.1.1/sub", "https://[::1]/sub", "https://[ff02::1]/sub", "https://printer.local/sub", "https://metadata.google.internal/"]) {
      expect(() => validateUpstreamUrl(value)).toThrow();
    }
  });
});
