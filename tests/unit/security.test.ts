import { describe, expect, it } from "vitest";
import { decryptJson, encryptJson, hmacSha256Hex, sha256Hex } from "../../src/worker/security/crypto";
import { hashPassword, verifyPassword } from "../../src/worker/security/password";
import { canonicalizeIpv4, validateUpstreamUrl } from "../../src/worker/security/safe-fetch";

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

  it("blocks encoded and short-form IPv4 loopback/private addresses", () => {
    // inet_aton style encodings of 127.0.0.1 and private ranges that would
    // slip past a naive dotted-quad check.
    for (const value of [
      "https://2130706433/sub", // 127.0.0.1 as a 32-bit integer
      "https://0x7f000001/sub", // hex
      "https://0177.0.0.1/sub", // octal first octet
      "https://127.1/sub", // short form
      "https://127.0.1/sub", // three-part short form
      "https://0xc0a80101/sub", // 192.168.1.1 in hex
      "https://3232235777/sub", // 192.168.1.1 as integer
    ]) {
      expect(() => validateUpstreamUrl(value)).toThrow();
    }
    // Public addresses in the same forms must still be allowed.
    expect(validateUpstreamUrl("https://8.8.8.8/sub").hostname).toBe("8.8.8.8");
  });

  it("blocks IPv4-mapped and NAT64 IPv6 loopback/private targets", () => {
    for (const value of [
      "https://[::ffff:127.0.0.1]/sub", // IPv4-mapped loopback (URL compresses to ::ffff:7f00:1)
      "https://[::ffff:192.168.0.1]/sub", // IPv4-mapped private
      "https://[64:ff9b::7f00:1]/sub", // NAT64 loopback
    ]) {
      expect(() => validateUpstreamUrl(value)).toThrow();
    }
    // A mapped *public* address stays reachable.
    expect(() => validateUpstreamUrl("https://[::ffff:8.8.8.8]/sub")).not.toThrow();
  });

  it("canonicalizes IPv4 encodings and ignores real hostnames", () => {
    expect(canonicalizeIpv4("2130706433")).toEqual([127, 0, 0, 1]);
    expect(canonicalizeIpv4("0x7f000001")).toEqual([127, 0, 0, 1]);
    expect(canonicalizeIpv4("0177.0.0.1")).toEqual([127, 0, 0, 1]);
    expect(canonicalizeIpv4("127.1")).toEqual([127, 0, 0, 1]);
    expect(canonicalizeIpv4("192.168.1.1")).toEqual([192, 168, 1, 1]);
    expect(canonicalizeIpv4("example.com")).toBeUndefined();
    expect(canonicalizeIpv4("sub.example.com")).toBeUndefined();
  });
});
