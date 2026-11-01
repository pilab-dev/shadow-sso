import { afterEach, describe, expect, it, vi } from "vitest";
import { preflightSilentAuthorize, silentLogin } from "../src/index.js";

const options = {
  issuer: "https://sso.example.com",
  clientId: "client-1",
  redirectUri: "https://app.example.com/callback",
  parentOrigin: "https://app.example.com",
  state: "state-1",
  timeoutMs: 100,
};

function mockFetch(headers: Record<string, string>, status = 200): void {
  const response = {
    ok: status >= 200 && status < 300,
    status,
    headers: new Headers(headers),
  } as Response;
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(response));
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
  document.querySelectorAll("iframe[data-sso-silent]").forEach((node) => node.remove());
});

describe("preflightSilentAuthorize", () => {
  it("accepts a matching frame-ancestors policy", async () => {
    mockFetch({
      "content-security-policy": "frame-ancestors https://app.example.com",
    });

    await expect(preflightSilentAuthorize(options)).resolves.toBeUndefined();
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/oauth2/silent-authorize"),
      expect.objectContaining({ method: "HEAD", mode: "cors" }),
    );
  });

  it("accepts a wildcard subdomain policy", async () => {
    mockFetch({
      "content-security-policy": "frame-ancestors https://*.example.com",
    });

    await expect(preflightSilentAuthorize(options)).resolves.toBeUndefined();
  });

  it("rejects X-Frame-Options: DENY", async () => {
    mockFetch({ "x-frame-options": "DENY" });
    const errorSpy = vi.spyOn(console, "error").mockImplementation(() => undefined);

    await expect(preflightSilentAuthorize(options)).rejects.toMatchObject({
      code: "frame_blocked",
    });
    expect(errorSpy).toHaveBeenCalled();
  });

  it("rejects frame-ancestors 'none'", async () => {
    mockFetch({
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    });
    vi.spyOn(console, "error").mockImplementation(() => undefined);

    await expect(preflightSilentAuthorize(options)).rejects.toMatchObject({
      code: "frame_blocked",
    });
  });

  it("rejects X-Frame-Options: SAMEORIGIN for a cross-origin parent", async () => {
    mockFetch({ "x-frame-options": "SAMEORIGIN" });
    vi.spyOn(console, "error").mockImplementation(() => undefined);

    await expect(preflightSilentAuthorize(options)).rejects.toMatchObject({
      code: "frame_blocked",
    });
  });

  it("logs a warning and continues when the preflight is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("CORS")));
    const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    await expect(preflightSilentAuthorize(options)).resolves.toBeUndefined();
    expect(warnSpy).toHaveBeenCalled();
  });

  it("stops silentLogin before creating the iframe when framing is blocked", async () => {
    mockFetch({ "x-frame-options": "DENY" });
    vi.spyOn(console, "error").mockImplementation(() => undefined);

    await expect(
      silentLogin({ ...options, parentOrigin: window.location.origin, preflight: true }),
    ).rejects.toMatchObject({ code: "frame_blocked" });

    expect(document.querySelector("iframe[data-sso-silent]")).toBeNull();
  });
});
