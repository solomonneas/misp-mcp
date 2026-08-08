import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { getConfig } from "../src/config.js";

const REQUIRED_ENV = {
  MISP_URL: "https://misp.example.com",
  MISP_API_KEY: "test-api-key",
} as const;

describe("getConfig MISP_TIMEOUT", () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv, ...REQUIRED_ENV };
    delete process.env.MISP_TIMEOUT;
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it("defaults to 30 seconds when MISP_TIMEOUT is unset", () => {
    expect(getConfig().timeout).toBe(30_000);
  });

  it("accepts a positive integer within the documented maximum", () => {
    process.env.MISP_TIMEOUT = "120";
    expect(getConfig().timeout).toBe(120_000);
  });

  it("accepts the documented maximum of 3600 seconds", () => {
    process.env.MISP_TIMEOUT = "3600";
    expect(getConfig().timeout).toBe(3_600_000);
  });

  it.each([
    ["abc"],
    ["0"],
    ["-5"],
    ["30seconds"],
    ["30.5"],
    [""],
    [" 30"],
    ["30 "],
  ])("rejects malformed MISP_TIMEOUT value %j", (value) => {
    process.env.MISP_TIMEOUT = value;
    expect(() => getConfig()).toThrow(/^MISP_TIMEOUT/);
  });

  it("rejects values above the documented maximum", () => {
    process.env.MISP_TIMEOUT = "3601";
    expect(() => getConfig()).toThrow(/^MISP_TIMEOUT/);
  });
});
