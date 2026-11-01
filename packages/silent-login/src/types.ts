export type SilentLoginErrorCode =
  | "login_required"
  | "consent_required"
  | "origin_not_allowed"
  | "access_denied"
  | "invalid_request"
  | "invalid_client"
  | "invalid_scope"
  | "server_error"
  | "timeout"
  | "frame_blocked"
  | "frame_error"
  | "aborted"
  | "not_browser"
  | "invalid_config";

export interface SilentLoginOptions {
  /** SSO issuer/base URL, for example https://sso.pilab.hu */
  issuer: string;
  /** OAuth client id */
  clientId: string;
  /** Registered redirect URI on the application origin */
  redirectUri: string;
  /** OAuth scopes, defaults to "openid profile email" */
  scope?: string;
  /** CSRF state. Generated when omitted. */
  state?: string;
  /** OIDC nonce. Optional unless the caller needs it in the ID token. */
  nonce?: string;
  /** PKCE challenge. Use generatePkcePair() to create one. */
  codeChallenge?: string;
  /** PKCE method, defaults to S256 */
  codeChallengeMethod?: "S256" | "plain";
  /** Parent window origin. Defaults to window.location.origin. */
  parentOrigin?: string;
  /** Check the SSO frame policy headers before creating the iframe. Defaults to true. */
  preflight?: boolean;
  /** Timeout in milliseconds, defaults to 10000 */
  timeoutMs?: number;
  /** Optional extra query parameters. Critical parameters cannot be overridden. */
  extraParams?: Record<string, string>;
  /** Accessible iframe title, defaults to "Silent authentication" */
  iframeTitle?: string;
  /** Optional cancellation signal */
  signal?: AbortSignal;
}

export interface SilentLoginSuccess {
  code: string;
  state: string;
}

export interface SilentAuthorizeUrl {
  url: string;
  state: string;
  /** SSO origin used to validate postMessage events */
  origin: string;
  /** Parent window origin passed to the SSO */
  parentOrigin: string;
}

export interface PkcePair {
  verifier: string;
  challenge: string;
  method: "S256";
}

export interface SilentResultMessage {
  type: "sso-silent-result";
  state?: string;
  code?: string;
  error?: string;
  error_description?: string;
}
