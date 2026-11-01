import { randomHex } from "./crypto.js";
import { SilentLoginError } from "./errors.js";
import type { SilentAuthorizeUrl, SilentLoginOptions } from "./types.js";

const CRITICAL_PARAMS = new Set([
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "nonce",
  "parent_origin",
  "code_challenge",
  "code_challenge_method",
]);

function parseAbsoluteUrl(raw: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    throw new SilentLoginError("invalid_config", `${label} must be an absolute URL.`);
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new SilentLoginError("invalid_config", `${label} must use http or https.`);
  }
  return parsed;
}

function normalizeParentOrigin(raw: string): string {
  const parsed = parseAbsoluteUrl(raw, "parentOrigin");
  if (parsed.username || parsed.password) {
    throw new SilentLoginError("invalid_config", "parentOrigin must not contain credentials.");
  }
  if (parsed.pathname !== "/" && parsed.pathname !== "") {
    throw new SilentLoginError("invalid_config", "parentOrigin must not contain a path.");
  }
  if (parsed.search || parsed.hash) {
    throw new SilentLoginError("invalid_config", "parentOrigin must not contain a query or fragment.");
  }
  return parsed.origin;
}

/**
 * Builds the silent-authorize iframe URL. Exposed for advanced integrations and
 * tests; most callers should use silentLogin().
 */
export function buildSilentAuthorizeUrl(options: SilentLoginOptions): SilentAuthorizeUrl {
  if (!options.clientId) {
    throw new SilentLoginError("invalid_config", "clientId is required.");
  }

  const issuerUrl = parseAbsoluteUrl(options.issuer, "issuer");
  const redirectUrl = parseAbsoluteUrl(options.redirectUri, "redirectUri");
  const parentOrigin =
    options.parentOrigin ??
    (typeof window !== "undefined" && window.location?.origin ? window.location.origin : undefined);

  if (!parentOrigin) {
    throw new SilentLoginError(
      "not_browser",
      "parentOrigin is required when buildSilentAuthorizeUrl runs outside the browser.",
    );
  }

  const state = options.state ?? randomHex(16);
  const endpoint = new URL("/oauth2/silent-authorize", issuerUrl.origin);
  const normalizedParentOrigin = normalizeParentOrigin(parentOrigin);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: options.clientId,
    redirect_uri: redirectUrl.toString(),
    scope: options.scope ?? "openid profile email",
    state,
    parent_origin: normalizedParentOrigin,
  });

  if (options.nonce) {
    params.set("nonce", options.nonce);
  }
  if (options.codeChallenge) {
    params.set("code_challenge", options.codeChallenge);
    params.set("code_challenge_method", options.codeChallengeMethod ?? "S256");
  }
  for (const [key, value] of Object.entries(options.extraParams ?? {})) {
    if (!CRITICAL_PARAMS.has(key)) {
      params.set(key, value);
    }
  }

  endpoint.search = params.toString();
  return {
    url: endpoint.toString(),
    state,
    origin: issuerUrl.origin,
    parentOrigin: normalizedParentOrigin,
  };
}
