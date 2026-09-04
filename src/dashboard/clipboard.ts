interface ClipboardEnvironment {
  isSecureContext: boolean;
  clipboard?: { writeText(text: string): Promise<void> };
  document: Document;
}

function browserEnvironment(): ClipboardEnvironment {
  return {
    isSecureContext: window.isSecureContext,
    clipboard: navigator.clipboard,
    document,
  };
}

export async function copyText(
  text: string,
  environment: ClipboardEnvironment = browserEnvironment(),
): Promise<boolean> {
  if (!text) return false;

  if (environment.isSecureContext && environment.clipboard?.writeText) {
    try {
      await environment.clipboard.writeText(text);
      return true;
    } catch {
      // Fall through for browsers that expose Clipboard API but reject it.
    }
  }

  const { document: doc } = environment;
  const activeElement = doc.activeElement as HTMLElement | null;
  const textarea = doc.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.setAttribute("aria-hidden", "true");
  textarea.style.position = "fixed";
  textarea.style.left = "-9999px";
  textarea.style.top = "0";
  textarea.style.opacity = "0";

  doc.body.appendChild(textarea);
  textarea.focus();
  textarea.select();
  textarea.setSelectionRange(0, textarea.value.length);

  try {
    return doc.execCommand("copy");
  } catch {
    return false;
  } finally {
    textarea.remove();
    activeElement?.focus?.();
  }
}
