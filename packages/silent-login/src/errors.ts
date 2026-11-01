import type { SilentLoginErrorCode } from "./types.js";

const DEFAULT_DESCRIPTIONS: Record<string, string> = {
  login_required: "No active SSO session was found.",
  consent_required: "The user is logged in but must approve the application.",
  origin_not_allowed: "The parent origin is not allowed to use silent login for this client.",
  access_denied: "The authorization request was denied.",
  invalid_request: "The silent login request was invalid.",
  invalid_client: "The OAuth client is invalid or inactive.",
  invalid_scope: "The requested scope is not allowed for this client.",
  server_error: "The SSO server could not complete silent login.",
  frame_blocked: "The SSO silent-login response cannot be framed by this origin.",
  timeout: "Silent login timed out.",
  frame_error: "The silent login iframe failed to load.",
};

export class SilentLoginError extends Error {
  readonly code: SilentLoginErrorCode;
  readonly description?: string;
  readonly state?: string;

  constructor(code: SilentLoginErrorCode, description?: string, state?: string) {
    super(description ?? DEFAULT_DESCRIPTIONS[code] ?? "Silent login failed.");
    this.name = "SilentLoginError";
    this.code = code;
    this.description = description;
    this.state = state;
  }
}

export function isSilentLoginError(value: unknown): value is SilentLoginError {
  return value instanceof SilentLoginError;
}

const KNOWN_ERROR_CODES = new Set<string>(Object.keys(DEFAULT_DESCRIPTIONS));

export function toSilentLoginErrorCode(value: string): SilentLoginErrorCode {
  if (KNOWN_ERROR_CODES.has(value)) {
    return value as SilentLoginErrorCode;
  }
  return "server_error";
}

export function serverErrorDescription(code: string, description?: string): string {
  if (description) {
    return description;
  }
  return DEFAULT_DESCRIPTIONS[code] ?? `SSO returned "${code}".`;
}
