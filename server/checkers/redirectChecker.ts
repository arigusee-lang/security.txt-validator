import type { CheckStatus } from "../types.js";
import { ssrfSafeFetch } from "../lib/ipCheck.js";

export interface RedirectCheckItem {
  check: string;
  status: CheckStatus;
  detail: string;
  ref?: string;
}

export interface RedirectResult {
  status: CheckStatus;
  httpsRedirect: boolean;
  wwwBehavior: string | null;
  items: RedirectCheckItem[];
  error?: string;
}

const OWASP_HTTPS = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html";
const GOOGLE_HTTPS = "https://developers.google.com/search/docs/crawling-indexing/https";

async function checkUrl(url: string, timeout: number): Promise<{ status: number; location: string | null } | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const res = await ssrfSafeFetch(url, { method: "HEAD", redirect: "manual", signal: controller.signal, headers: { "User-Agent": "security-txt-validator/1.0" } });
    clearTimeout(timer);
    return { status: res.status, location: res.headers.get("location") };
  } catch { return null; }
}

export async function checkRedirects(domain: string, timeout: number = 5000): Promise<RedirectResult> {
  const items: RedirectCheckItem[] = [];
  let httpsRedirect = false;
  let wwwBehavior: string | null = null;

  const httpResult = await checkUrl(`http://${domain}/`, timeout);
  if (httpResult) {
    if (httpResult.status >= 300 && httpResult.status < 400 && httpResult.location) {
      if (httpResult.location.startsWith("https://")) {
        httpsRedirect = true;
        items.push({ check: "HTTP → HTTPS redirect", status: "pass", detail: `Redirects to ${httpResult.location}`, ref: OWASP_HTTPS });
      } else {
        items.push({ check: "HTTP → HTTPS redirect", status: "warn", detail: `Redirects to ${httpResult.location} (not HTTPS)`, ref: OWASP_HTTPS });
      }
    } else if (httpResult.status === 200) {
      items.push({ check: "HTTP → HTTPS redirect", status: "fail", detail: "HTTP serves content without redirecting to HTTPS", ref: OWASP_HTTPS });
    } else {
      items.push({ check: "HTTP → HTTPS redirect", status: "info", detail: `HTTP returned status ${httpResult.status}` });
    }
  } else {
    items.push({ check: "HTTP → HTTPS redirect", status: "info", detail: "Could not connect via HTTP" });
  }

  const hasWww = domain.startsWith("www.");
  const altDomain = hasWww ? domain.slice(4) : `www.${domain}`;
  const altResult = await checkUrl(`https://${altDomain}/`, timeout);
  if (altResult) {
    if (altResult.status >= 300 && altResult.status < 400 && altResult.location) {
      wwwBehavior = `${altDomain} → ${altResult.location}`;
      items.push({ check: "www consistency", status: "pass", detail: `${altDomain} redirects properly`, ref: GOOGLE_HTTPS });
    } else if (altResult.status === 200) {
      wwwBehavior = `Both ${domain} and ${altDomain} serve content`;
      // SEO concern (duplicate content for search engines), not a security
      // issue — surface as info so it doesn't penalize the score.
      items.push({ check: "www consistency", status: "info", detail: `Both ${domain} and ${altDomain} serve content — consider redirecting one to the other for SEO`, ref: GOOGLE_HTTPS });
    } else {
      wwwBehavior = `${altDomain} returned ${altResult.status}`;
      items.push({ check: "www consistency", status: "info", detail: `${altDomain} returned status ${altResult.status}` });
    }
  } else {
    items.push({ check: "www consistency", status: "info", detail: `Could not connect to ${altDomain}` });
  }

  const overall: CheckStatus = items.some(i => i.status === "fail") ? "fail"
    : items.some(i => i.status === "warn") ? "warn" : "pass";

  return { status: overall, httpsRedirect, wwwBehavior, items };
}
