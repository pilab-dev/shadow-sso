import { SilentLoginError } from "./errors.js";
import { buildSilentAuthorizeUrl } from "./url.js";
import type { SilentLoginOptions } from "./types.js";

const PREFLIGHT_TIMEOUT_MS = 5_000;

interface FramePolicyDecision {
  allowed: boolean;
  reason: string;
}

/**
 * Checks the silent-authorize response headers before inserting the iframe.
 * Throws SilentLoginError("frame_blocked") when CSP/X-Frame-Options would
 * prevent the iframe from loading. Network/CORS failures are logged as a
 * warning and the caller continues with the iframe.
 */
export async function preflightSilentAuthorize(options: SilentLoginOptions): Promise<void> {
  const { url, origin, parentOrigin } = buildSilentAuthorizeUrl(options);
  await runPreflight(url, origin, parentOrigin, options.signal);
}

export async function runPreflight(
  url: string,
  ssoOrigin: string,
  parentOrigin: string,
  signal?: AbortSignal,
): Promise<void> {
  if (signal?.aborted) {
    throw new SilentLoginError("aborted", "Silent login was aborted.");
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), PREFLIGHT_TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, {
      method: "HEAD",
      mode: "cors",
      credentials: "omit",
      cache: "no-store",
      redirect: "follow",
      signal: controller.signal,
    });
  } catch (error) {
    clearTimeout(timer);
    if (signal?.aborted) {
      throw new SilentLoginError("aborted", "Silent login was aborted.");
    }
    console.warn(
      "[sso-silent-login] Unable to preflight SSO frame headers; continuing with iframe.",
      error,
    );
    return;
  } finally {
    clearTimeout(timer);
  }

  if (response.status === 404 || response.status === 405) {
    console.warn(
      `[sso-silent-login] SSO silent-login preflight is not supported (HTTP ${response.status}); continuing with iframe.`,
    );
    return;
  }
  if (!response.ok) {
    throw new SilentLoginError(
      "invalid_config",
      `Silent login preflight failed with HTTP ${response.status}.`,
    );
  }

  const csp = response.headers.get("content-security-policy") ?? "";
  const xfo = response.headers.get("x-frame-options") ?? "";
  const decision = evaluateFramePolicy(csp, xfo, ssoOrigin, parentOrigin);

  if (!decision.allowed) {
    const detail =
      `SSO frame policy blocks this origin (${decision.reason}). ` +
      `Content-Security-Policy=${csp || "(none)"} ` +
      `X-Frame-Options=${xfo || "(none)"}`;
    console.error("[sso-silent-login]", detail);
    throw new SilentLoginError("frame_blocked", detail);
  }
}

export function evaluateFramePolicy(
  csp: string,
  xfo: string,
  ssoOrigin: string,
  parentOrigin: string,
): FramePolicyDecision {
  const cspDecision = frameAncestorsDecision(csp, ssoOrigin, parentOrigin);
  if (cspDecision === "block") {
    return { allowed: false, reason: "Content-Security-Policy frame-ancestors" };
  }
  if (!xfoAllows(xfo, ssoOrigin, parentOrigin)) {
    return { allowed: false, reason: "X-Frame-Options" };
  }
  return { allowed: true, reason: "allowed" };
}

function frameAncestorsDecision(
  csp: string,
  ssoOrigin: string,
  parentOrigin: string,
): "allow" | "block" | "absent" {
  if (!csp.trim()) {
    return "absent";
  }

  let found = false;
  // A response may carry multiple policies separated by commas. Every policy
  // that specifies frame-ancestors must allow the parent origin.
  for (const policy of csp.split(",")) {
    for (const rawDirective of policy.split(";")) {
      const directive = rawDirective.trim();
      if (!directive) {
        continue;
      }
      const [name, ...values] = directive.split(/\s+/);
      if (name?.toLowerCase() !== "frame-ancestors") {
        continue;
      }
      found = true;
      if (values.length === 0) {
        return "block";
      }
      const matched = values.some((source) =>
        sourceMatchesOrigin(source, parentOrigin, ssoOrigin),
      );
      if (!matched) {
        return "block";
      }
    }
  }

  return found ? "allow" : "absent";
}

function xfoAllows(xfo: string, ssoOrigin: string, parentOrigin: string): boolean {
  const value = xfo.trim().toLowerCase();
  if (!value) {
    return true;
  }
  if (value === "deny") {
    return false;
  }
  if (value === "sameorigin") {
    return parentOrigin.toLowerCase() === ssoOrigin.toLowerCase();
  }
  const allowFrom = value.match(/^allow-from\s+(.+)$/);
  if (allowFrom?.[1]) {
    try {
      return new URL(allowFrom[1]).origin === parentOrigin;
    } catch {
      return false;
    }
  }
  // Unknown legacy value: do not report a false block.
  return true;
}

function sourceMatchesOrigin(source: string, parentOrigin: string, ssoOrigin: string): boolean {
  const value = source.trim().toLowerCase();
  const origin = parentOrigin.toLowerCase();

  if (!value) {
    return false;
  }
  if (value === "*") {
    return true;
  }
  if (value === "'none'") {
    return false;
  }
  if (value === "'self'") {
    return origin === ssoOrigin.toLowerCase();
  }
  if (value === "http:" || value === "https:") {
    return origin.startsWith(value);
  }

  // https://*.example.com and optional wildcard port
  const wildcard = value.match(/^(https?):\/\/\*\.([^/:]+)(?::(\*|\d+))?$/);
  if (wildcard) {
    const [, scheme, domain, port] = wildcard;
    try {
      const parsed = new URL(origin);
      if (parsed.protocol !== `${scheme}:`) {
        return false;
      }
      if (parsed.hostname !== domain && !parsed.hostname.endsWith(`.${domain}`)) {
        return false;
      }
      if (port && port !== "*" && parsed.port !== port) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  if (value.startsWith("http://") || value.startsWith("https://")) {
    try {
      return new URL(value).origin === new URL(origin).origin;
    } catch {
      return false;
    }
  }

  // Host source without a scheme, for example app.example.com
  try {
    return value === new URL(origin).host;
  } catch {
    return false;
  }
}
