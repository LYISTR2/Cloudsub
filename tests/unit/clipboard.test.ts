import { describe, expect, it, vi } from "vitest";
import { copyText } from "../../src/dashboard/clipboard";

function fakeEnvironment(execResult: boolean | Error = true) {
  let active: { focus: ReturnType<typeof vi.fn> } | null = { focus: vi.fn() };
  const textarea = {
    value: "",
    style: {} as Record<string, string>,
    setAttribute: vi.fn(),
    focus: vi.fn(() => { active = textarea; }),
    select: vi.fn(),
    setSelectionRange: vi.fn(),
    remove: vi.fn(),
  };
  const originalActive = active;
  const document = {
    get activeElement() { return active; },
    createElement: vi.fn(() => textarea),
    body: { appendChild: vi.fn() },
    execCommand: vi.fn(() => {
      if (execResult instanceof Error) throw execResult;
      return execResult;
    }),
  };
  return {
    environment: { isSecureContext: false, document: document as unknown as Document },
    document,
    textarea,
    originalActive,
  };
}

describe("copyText", () => {
  it("uses Clipboard API in a secure context", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const { environment, document } = fakeEnvironment();

    await expect(copyText("https://example.com/sub", {
      ...environment,
      isSecureContext: true,
      clipboard: { writeText },
    })).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("https://example.com/sub");
    expect(document.createElement).not.toHaveBeenCalled();
  });

  it("falls back to execCommand in an insecure context and restores focus", async () => {
    const { environment, document, textarea, originalActive } = fakeEnvironment();

    await expect(copyText("http://example.com/sub", environment)).resolves.toBe(true);
    expect(document.execCommand).toHaveBeenCalledWith("copy");
    expect(textarea.value).toBe("http://example.com/sub");
    expect(textarea.remove).toHaveBeenCalledOnce();
    expect(originalActive?.focus).toHaveBeenCalledOnce();
  });

  it("returns false and cleans up when fallback copy throws", async () => {
    const { environment, textarea, originalActive } = fakeEnvironment(new Error("copy blocked"));

    await expect(copyText("http://example.com/sub", environment)).resolves.toBe(false);
    expect(textarea.remove).toHaveBeenCalledOnce();
    expect(originalActive?.focus).toHaveBeenCalledOnce();
  });
});
