import { base64UrlEncode, randomHex } from "./crypto.js";
import { SilentLoginError } from "./errors.js";
import type { PkcePair } from "./types.js";

/**
 * Generates a PKCE verifier/challenge pair using SHA-256.
 * Keep the verifier and send it to /oauth2/token when exchanging the code.
 */
export async function generatePkcePair(): Promise<PkcePair> {
  if (!globalThis.crypto?.subtle) {
    throw new SilentLoginError(
      "not_browser",
      "Web Crypto (subtle.digest) is required for PKCE. Use HTTPS or localhost.",
    );
  }

  const verifier = randomHex(32);
  const digest = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );

  return {
    verifier,
    challenge: base64UrlEncode(new Uint8Array(digest)),
    method: "S256",
  };
}
