import {
  SilentLoginError,
  serverErrorDescription,
  toSilentLoginErrorCode,
} from "./errors.js";
import { runPreflight } from "./preflight.js";
import { buildSilentAuthorizeUrl } from "./url.js";
import type {
  SilentLoginErrorCode,
  SilentLoginOptions,
  SilentLoginSuccess,
  SilentResultMessage,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const MESSAGE_TYPE = "sso-silent-result";

function isSilentResultMessage(value: unknown): value is SilentResultMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  return (value as { type?: unknown }).type === MESSAGE_TYPE;
}

/**
 * Performs iframe-based silent login.
 *
 * Resolves with an authorization code when the user already has a valid SSO
 * session. Rejects with a SilentLoginError for login_required,
 * consent_required, origin_not_allowed, timeout, and related failures.
 */
export async function silentLogin(options: SilentLoginOptions): Promise<SilentLoginSuccess> {
  if (typeof window === "undefined" || typeof document === "undefined") {
    throw new SilentLoginError("not_browser", "silentLogin requires a browser environment.");
  }
  if (options.signal?.aborted) {
    throw new SilentLoginError("aborted", "Silent login was aborted.");
  }

  const { url, state, origin, parentOrigin } = buildSilentAuthorizeUrl(options);
  if (window.location.origin && parentOrigin !== window.location.origin) {
    throw new SilentLoginError(
      "invalid_config",
      "parentOrigin must match window.location.origin in the browser.",
    );
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new SilentLoginError("invalid_config", "timeoutMs must be a positive number.");
  }

  if (options.preflight !== false) {
    await runPreflight(url, origin, parentOrigin, options.signal);
  }

  return await new Promise<SilentLoginSuccess>((resolve, reject) => {
    let settled = false;
    let iframe: HTMLIFrameElement | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const cleanup = () => {
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      window.removeEventListener("message", onMessage);
      options.signal?.removeEventListener("abort", onAbort);
      if (iframe) {
        iframe.remove();
        iframe = null;
      }
    };

    const finish = (callback: () => void) => {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback();
    };

    const fail = (code: SilentLoginErrorCode, description?: string, messageState?: string) => {
      finish(() => reject(new SilentLoginError(code, description, messageState)));
    };

    const onMessage = (event: MessageEvent) => {
      if (event.origin !== origin) {
        return;
      }
      // event.source is normally the iframe window. Ignore messages from other
      // windows when the browser exposes it.
      if (iframe && event.source && event.source !== iframe.contentWindow) {
        return;
      }
      if (!isSilentResultMessage(event.data)) {
        return;
      }

      const message = event.data;
      if (message.state !== state) {
        return;
      }
      if (message.error) {
        fail(
          toSilentLoginErrorCode(message.error),
          serverErrorDescription(message.error, message.error_description),
          message.state,
        );
        return;
      }

      const code = message.code;
      if (!code) {
        fail("server_error", "Silent login returned no authorization code.", state);
        return;
      }

      finish(() => resolve({ code, state }));
    };

    const onAbort = () => fail("aborted", "Silent login was aborted.");

    window.addEventListener("message", onMessage);
    options.signal?.addEventListener("abort", onAbort, { once: true });

    timer = setTimeout(() => {
      fail(
        "timeout",
        "Silent login timed out. The iframe may have been blocked by CSP/X-Frame-Options, " +
          "third-party cookie policy, or the SSO did not respond.",
      );
    }, timeoutMs);

    iframe = document.createElement("iframe");
    iframe.title = options.iframeTitle ?? "Silent authentication";
    iframe.referrerPolicy = "no-referrer";
    iframe.setAttribute("aria-hidden", "true");
    iframe.setAttribute("data-sso-silent", state);
    iframe.style.position = "absolute";
    iframe.style.width = "0";
    iframe.style.height = "0";
    iframe.style.border = "0";
    iframe.style.visibility = "hidden";
    iframe.addEventListener("error", () => {
      fail("frame_error", "The silent login iframe failed to load.");
    });
    iframe.src = url;
    (document.body ?? document.documentElement).appendChild(iframe);
  });
}
