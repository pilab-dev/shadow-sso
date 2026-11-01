import { afterEach, describe, expect, it, vi } from "vitest";
import { silentLogin } from "../src/index.js";

const baseOptions = {
  issuer: "https://sso.example.com",
  clientId: "client-1",
  redirectUri: `${window.location.origin}/callback`,
  parentOrigin: window.location.origin,
  state: "state-1",
  timeoutMs: 500,
  preflight: false,
};

function dispatchResult(data: unknown, origin = "https://sso.example.com"): void {
  window.dispatchEvent(new MessageEvent("message", { data, origin }));
}

afterEach(() => {
  document.querySelectorAll("iframe[data-sso-silent]").forEach((node) => node.remove());
  vi.useRealTimers();
});

describe("silentLogin", () => {
  it("resolves with the authorization code", async () => {
    const promise = silentLogin(baseOptions);

    dispatchResult({
      type: "sso-silent-result",
      state: "state-1",
      code: "code-123",
    });

    await expect(promise).resolves.toEqual({ code: "code-123", state: "state-1" });
    expect(document.querySelector("iframe[data-sso-silent]")).toBeNull();
  });

  it("rejects with login_required", async () => {
    const promise = silentLogin(baseOptions);

    dispatchResult({
      type: "sso-silent-result",
      state: "state-1",
      error: "login_required",
    });

    await expect(promise).rejects.toMatchObject({
      code: "login_required",
      state: "state-1",
    });
    expect(document.querySelector("iframe[data-sso-silent]")).toBeNull();
  });

  it("rejects with origin_not_allowed", async () => {
    const promise = silentLogin(baseOptions);

    dispatchResult({
      type: "sso-silent-result",
      state: "state-1",
      error: "origin_not_allowed",
    });

    await expect(promise).rejects.toMatchObject({
      code: "origin_not_allowed",
      state: "state-1",
    });
  });

  it("ignores messages from another origin and times out", async () => {
    vi.useFakeTimers();
    const promise = silentLogin({ ...baseOptions, timeoutMs: 50 });
    const rejection = expect(promise).rejects.toMatchObject({ code: "timeout" });

    dispatchResult(
      { type: "sso-silent-result", state: "state-1", code: "stolen" },
      "https://evil.example.com",
    );
    await vi.advanceTimersByTimeAsync(50);
    await rejection;

    expect(document.querySelector("iframe[data-sso-silent]")).toBeNull();
  });

  it("can be aborted", async () => {
    const controller = new AbortController();
    const promise = silentLogin({ ...baseOptions, signal: controller.signal });
    const rejection = expect(promise).rejects.toMatchObject({ code: "aborted" });

    controller.abort();
    await rejection;

    expect(document.querySelector("iframe[data-sso-silent]")).toBeNull();
  });

  it("rejects invalid configuration", async () => {
    await expect(
      silentLogin({
        ...baseOptions,
        redirectUri: "myapp://callback",
      }),
    ).rejects.toMatchObject({ code: "invalid_config" });
  });
});
