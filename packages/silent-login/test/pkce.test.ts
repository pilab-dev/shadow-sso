// @vitest-environment node
import { describe, expect, it } from "vitest";
import { generatePkcePair } from "../src/index.js";

describe("generatePkcePair", () => {
  it("generates a valid S256 verifier and challenge", async () => {
    const pair = await generatePkcePair();

    expect(pair.method).toBe("S256");
    expect(pair.verifier).toMatch(/^[0-9a-f]{64}$/);
    expect(pair.challenge).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(pair.challenge).not.toContain("=");
  });
});
