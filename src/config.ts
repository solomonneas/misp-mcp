/** Maximum allowed MISP_TIMEOUT value in seconds (1 hour). */
export const MISP_TIMEOUT_MAX_SECONDS = 3600;

const MISP_TIMEOUT_DEFAULT_SECONDS = 30;

export interface MispConfig {
  url: string;
  apiKey: string;
  verifySsl: boolean;
  timeout: number;
}

export function parseTimeoutSeconds(raw: string | undefined): number {
  const value = raw ?? String(MISP_TIMEOUT_DEFAULT_SECONDS);

  if (!/^[1-9]\d*$/.test(value)) {
    throw new Error(
      `MISP_TIMEOUT must be a positive integer between 1 and ${MISP_TIMEOUT_MAX_SECONDS} seconds (got ${JSON.stringify(raw ?? "")})`,
    );
  }

  const seconds = Number(value);
  if (seconds > MISP_TIMEOUT_MAX_SECONDS) {
    throw new Error(
      `MISP_TIMEOUT must be a positive integer between 1 and ${MISP_TIMEOUT_MAX_SECONDS} seconds (got ${seconds})`,
    );
  }

  return seconds;
}

export function getConfig(): MispConfig {
  const url = process.env.MISP_URL;
  if (!url) {
    throw new Error("MISP_URL environment variable is required");
  }

  const apiKey = process.env.MISP_API_KEY;
  if (!apiKey) {
    throw new Error("MISP_API_KEY environment variable is required");
  }

  const verifySsl = process.env.MISP_VERIFY_SSL !== "false";
  const timeout = parseTimeoutSeconds(process.env.MISP_TIMEOUT) * 1000;

  return {
    url: url.replace(/\/+$/, ""),
    apiKey,
    verifySsl,
    timeout,
  };
}
