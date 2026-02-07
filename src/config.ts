export interface MispConfig {
  url: string;
  apiKey: string;
  verifySsl: boolean;
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

  return {
    url: url.replace(/\/+$/, ""),
    apiKey,
    verifySsl,
  };
}
