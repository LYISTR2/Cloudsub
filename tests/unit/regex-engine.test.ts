import { describe, expect, it } from "vitest";
import { compileSafePattern, runSafePattern, validateSafePattern } from "../../src/worker/security/regex";

function test(pattern: string, text: string): boolean | undefined {
  const compiled = compileSafePattern(pattern);
  if (!compiled) return undefined;
  return runSafePattern(compiled).test(text);
}

describe("safe regex engine — supported syntax", () => {
  const cases: Array<[string, string, boolean]> = [
    ["Tokyo", "tokyo 01", true], // case-insensitive by default
    ["^JP", "JP 01", true],
    ["^JP", "Tokyo JP", false],
    ["01$", "Tokyo 01", true],
    ["01$", "Tokyo 010", false],
    ["[0-9]{2}", "node 42", true],
    ["\\d+", "abc123", true],
    ["a|b", "xyz b", true],
    ["(premium|free)", "premium node", true],
    ["(?:x|y)+", "xxy", true],
    ["\\p{L}+", "東京-01", true],
    ["节点", "东京节点", true],
    ["HK\\s*01", "HK 01", true],
    ["a{2,3}", "aaa", true],
    ["a{2,3}", "a", false],
    ["a{2,}", "aa", true],
    ["a{2,}", "a", false],
    ["a{0,2}", "b", true], // zero-width match allowed by the quantifier
    ["a*", "b", true], // a* matches empty
    ["x.*y", "xaaaaay", true],
    ["[^a-z]", "ABC!", true],
    ["\\.", "a.b", true],
    ["(x|y)z", "yz", true],
    ["(x|y)z", "xz", true],
    ["(x|y)z", "x", false],
    ["(a+)+$", "aaa", true],
    ["(a+)+$", "aaa!", false],
    ["node\\d", "node42", true],
  ];
  for (const [pattern, text, expected] of cases) {
    it(`pattern ${JSON.stringify(pattern)} ${expected ? "matches" : "does not match"} ${JSON.stringify(text)}`, () => {
      expect(test(pattern, text)).toBe(expected);
    });
  }
});

describe("safe regex engine — validation", () => {
  it("rejects constructs that need backtracking or are ambiguous", () => {
    for (const bad of ["a{501}", "(?=a)", "(?!a)", "(?<=a)", "(?<name>a)", "\\1", "(a)(b)\\1", "(?i)a", "(?>a)", "a{2,1}", "(a]{2}"]) {
      expect(validateSafePattern(bad), bad).not.toBeNull();
    }
  });

  it("accepts ReDoS classics because execution is linear-time", () => {
    for (const good of ["(a+)+$", "(a|a)*b", "(a*)*$", "a*a*a*a*a*a*a*a*b", "a{500}"]) {
      expect(validateSafePattern(good), good).toBeNull();
    }
  });

  it("rejects over-length patterns", () => {
    expect(validateSafePattern("a".repeat(201))).not.toBeNull();
  });

  it("returns a human-readable reason", () => {
    expect(validateSafePattern("(?=a)")).toContain("不支持的表达式语法");
  });
});

describe("safe regex engine — linear-time behavior", () => {
  it("handles nested-quantifier ReDoS patterns in linear time on long inputs", () => {
    const patterns = ["(a+)+$", "(a|a)*b", "(a*)*c", "a*a*a*a*a*a*a*a*a*b"];
    for (const pattern of patterns) {
      const compiled = compileSafePattern(pattern);
      expect(compiled).not.toBeNull();
      const started = Date.now();
      const result = runSafePattern(compiled!).test("a".repeat(20_000) + "!");
      expect(result).toBe(false);
      expect(Date.now() - started).toBeLessThan(1000);
    }
    // And a genuine match still succeeds.
    const compiled = compileSafePattern("(a+)+$");
    expect(runSafePattern(compiled!).test("a".repeat(20_000))).toBe(true);
  });

  it("caps input length at the documented bound", () => {
    const compiled = compileSafePattern("a+");
    expect(runSafePattern(compiled!).test("a".repeat(60_000))).toBe(true);
  });
});

describe("safe regex engine — rename replacement", () => {
  it("supports $1..$9, $& and $$", () => {
    const compiled = compileSafePattern("(Tokyo) (\\d+)");
    const safe = runSafePattern(compiled!);
    expect(safe.replace("Tokyo 01", "JP-$2")).toBe("JP-01");
    // The whole match (including the space) is replaced.
    expect(safe.replace("Tokyo 01", "[$1]")).toBe("[Tokyo]");
    expect(safe.replace("Tokyo 01", "$&!")).toBe("Tokyo 01!");
    expect(safe.replace("Tokyo 01", "$$")).toBe("$");
  });

  it("replaces all non-overlapping matches", () => {
    const compiled = compileSafePattern("HK");
    expect(runSafePattern(compiled!).replace("HK-01-HK-02", "SG")).toBe("SG-01-SG-02");
  });

  it("renames with .* exactly like native /.*/g (greedy whole-name + trailing empty)", () => {
    const compiled = compileSafePattern(".*");
    expect(runSafePattern(compiled!).replace("Tokyo 01", "Renamed")).toBe("RenamedRenamed");
    expect("Tokyo 01".replace(/.*/g, "Renamed")).toBe("RenamedRenamed");
  });
});

describe("safe regex engine — semantics vs native", () => {
  const corpus = ["Tokyo 01", "HK-SG-01", "Premium + Fast", "东京节点", "node_42", "a.b.c", "abc123", "香港-01", "US-LA-P3"];
  const patterns = ["tokyo", "^HK", "01$", "\\d+", "[a-z]{3}\\d{2}", "\\.", "节点", "\\p{L}+", "HK|SG", "(\\d{2})", "[^a-z0-9 ]"];
  for (const pattern of patterns) {
    it(`matches like native RegExp for ${JSON.stringify(pattern)}`, () => {
      const compiled = compileSafePattern(pattern);
      expect(compiled).not.toBeNull();
      const safe = runSafePattern(compiled!);
      for (const text of corpus) {
        const native = new RegExp(pattern, "iu").test(text);
        expect(safe.test(text), `${pattern} on ${text}`).toBe(native);
      }
    });
  }
});
