import dns from "node:dns/promises";
import { isBlockedIp } from "./ipCheck.js";
import type { ProxyFetchResponse, ProxyFetchError } from "../types.js";

const MAX_REDIRECTS = 3;
const TIMEOUT_MS = 10_000;
const MAX_BODY_BYTES = 100 * 1024; // 100 KB

/**
 * Safely converts any thrown error into a ProxyFetchError.
 */
function toProxyError(err: any): ProxyFetchError {
  if (err && typeof err === "object" && err.error) {
    return {
      success: false as const,
      error: err.error,
      message: err.message || "An error occurred.",
      ...(err.httpStatus ? { httpStatus: err.httpStatus } : {}),
    };
  }
  return {
    success: false as const,
    error: "internal",
    message: err?.message || "An unexpected error occurred.",
  };
}

/**
 * Resolves a hostname and checks all IPs against blocked ranges.
 * Returns the first non-blocked IP, or throws with "ssrf_blocked" / "dns_failure".
 */
async function resolveAndCheck(hostname: string): Promise<void> {
  let addresses: string[];
  try {
    const result = await dns.resolve4(hostname).catch(() => []);
    const result6 = await dns.resolve6(hostname).catch(() => []);
    addresses = [...result, ...result6];
  } catch {
    throw { error: "dns_failure" as const, message: "Could not resolve domain." };
  }

  if (addresses.length === 0) {
    throw { error: "dns_failure" as const, message: "Could not resolve domain." };
  }

  for (const ip of addresses) {
    if (isBlockedIp(ip)) {
      throw { error: "ssrf_blocked" as const, message: "Restricted address." };
    }
  }
}

/**
 * Fetches a URL with SSRF protections: DNS check, redirect IP checks,
 * timeout, and body size limit.
 */
async function fetchWithProtection(
  url: string,
  redirectChain: string[],
  redirectCount: number
): Promise<{ body: string; contentType: string; finalUrl: string; redirectChain: string[] }> {
  const parsed = new URL(url);

  if (parsed.protocol !== "https:") {
    throw { error: "ssrf_blocked" as const, message: "Only HTTPS is allowed." };
  }

  await resolveAndCheck(parsed.hostname);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  let response: Response;
  try {
    response = await fetch(url, {
      signal: controller.signal,
      redirect: "manual",
      headers: { "User-Agent": "security-txt-validator/1.0" },
    });
  } catch (err: any) {
    clearTimeout(timer);
    if (err?.name === "AbortError") {
      throw { error: "timeout" as const, message: "Remote server timed out." };
    }
    throw { error: "dns_failure" as const, message: "Could not resolve domain." };
  } finally {
    clearTimeout(timer);
  }

  // Handle redirects manually so we can IP-check each hop
  if (response.status >= 300 && response.status < 400) {
    const location = response.headers.get("location");
    if (!location) {
      throw { error: "http_error" as const, message: `Redirect without Location header.`, httpStatus: response.status };
    }

    if (redirectCount >= MAX_REDIRECTS) {
      throw { error: "too_many_redirects" as const, message: "Too many redirects." };
    }

    const redirectUrl = new URL(location, url).toString();
    redirectChain.push(redirectUrl);
    return fetchWithProtection(redirectUrl, redirectChain, redirectCount + 1);
  }

  if (!response.ok) {
    throw { error: "http_error" as const, message: `HTTP ${response.status}`, httpStatus: response.status };
  }

  // Read body with size limit
  const reader = response.body?.getReader();
  if (!reader) {
    throw { error: "http_error" as const, message: "Empty response body." };
  }

  const chunks: Uint8Array[] = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > MAX_BODY_BYTES) {
      reader.cancel();
      throw { error: "size_limit" as const, message: "Response exceeds 100 KB limit." };
    }
    chunks.push(value);
  }

  const decoder = new TextDecoder();
  const body = chunks.map((c) => decoder.decode(c, { stream: true })).join("") + decoder.decode();
  const contentType = response.headers.get("content-type") || "";

  return { body, contentType, finalUrl: url, redirectChain };
}

/**
 * SSRF-safe fetch for security.txt files.
 * Tries /.well-known/security.txt first, falls back to /security.txt.
 * Validates Content-Type contains text/plain.
 */
export async function safeFetch(domain: string): Promise<ProxyFetchResponse | ProxyFetchError> {
  const wellKnownUrl = `https://${domain}/.well-known/security.txt`;
  const fallbackUrl = `https://${domain}/security.txt`;

  let result: { body: string; contentType: string; finalUrl: string; redirectChain: string[] };
  let wellKnownFound = true;
  let fallbackUsed = false;

  try {
    result = await fetchWithProtection(wellKnownUrl, [], 0);
  } catch (err: any) {
    // If it's a 404, try fallback
    if (err?.error === "http_error" && err?.httpStatus === 404) {
      wellKnownFound = false;
      fallbackUsed = true;
      try {
        result = await fetchWithProtection(fallbackUrl, [], 0);
      } catch (fallbackErr: any) {
        if (fallbackErr?.error === "http_error" && fallbackErr?.httpStatus === 404) {
          return { success: false, error: "not_found", message: "No security.txt file found." };
        }
        return toProxyError(fallbackErr);
      }
    } else {
      return toProxyError(err);
    }
  }

  // Verify Content-Type
  if (!result.contentType.includes("text/plain")) {
    return {
      success: false,
      error: "invalid_content_type",
      message: "Expected text/plain content type.",
    };
  }

  return {
    success: true,
    content: result.body,
    contentType: result.contentType,
    fetchedFrom: result.finalUrl,
    redirectChain: result.redirectChain,
    wellKnownFound,
    fallbackUsed,
  };
}
