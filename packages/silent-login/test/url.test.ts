import { describe, expect, it } from "vitest";
import { buildSilentAuthorizeUrl, SilentLoginError } from "../src/index.js";

const baseOptions = {
  issuer: "https://sso.example.com",
  clientId: "client-1",
  redirectUri: "https://app.example.com/callback",
  parentOrigin: "https://app.example.com",
};

describe("buildSilentAuthorizeUrl", () => {
  it("builds the silent authorize URL", () => {
    const result = buildSilentAuthorizeUrl({
      ...baseOptions,
      state: "state-1",
      nonce: "nonce-1",
      scope: "openid profile email",
      codeChallenge: "challenge-1",
      codeChallengeMethod: "S256",
    });

    expect(result.origin).toBe("https://sso.example.com");
    expect(result.parentOrigin).toBe("https://app.example.com");
    expect(result.state).toBe("state-1");

    const url = new URL(result.url);
    expect(url.origin).toBe("https://sso.example.com");
    expect(url.pathname).toBe("/oauth2/silent-authorize");
    expect(url.searchParams.get("response_type")).toBe("code");
    expect(url.searchParams.get("client_id")).toBe("client-1");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.example.com/callback");
    expect(url.searchParams.get("scope")).toBe("openid profile email");
    expect(url.searchParams.get("state")).toBe("state-1");
    expect(url.searchParams.get("nonce")).toBe("nonce-1");
    expect(url.searchParams.get("parent_origin")).toBe("https://app.example.com");
    expect(url.searchParams.get("code_challenge")).toBe("challenge-1");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
  });

  it("generates a state when none is supplied", () => {
    const result = buildSilentAuthorizeUrl(baseOptions);
    expect(result.state).toMatch(/^[0-9a-f]{32}$/);
  });

  it("does not let extraParams override critical parameters", () => {
    const result = buildSilentAuthorizeUrl({
      ...baseOptions,
      state: "state-1",
      extraParams: {
        client_id: "attacker",
        redirect_uri: "https://evil.example.com/callback",
        parent_origin: "https://evil.example.com",
        prompt: "none",
      },
    });

    const url = new URL(result.url);
    expect(url.searchParams.get("client_id")).toBe("client-1");
    expect(url.searchParams.get("redirect_uri")).toBe("https://app.example.com/callback");
    expect(url.searchParams.get("parent_origin")).toBe("https://app.example.com");
    expect(url.searchParams.get("prompt")).toBe("none");
  });

  it("rejects a parent origin with a path", () => {
    expect(() =>
      buildSilentAuthorizeUrl({
        ...baseOptions,
        parentOrigin: "https://app.example.com/nested",
      }),
    ).toThrow(SilentLoginError);
  });

  it("rejects a non-http redirect URI", () => {
    expect(() =>
      buildSilentAuthorizeUrl({
        ...baseOptions,
        redirectUri: "myapp://callback",
      }),
    ).toThrow(SilentLoginError);
  });
});
