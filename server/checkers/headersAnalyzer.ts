import type { CheckStatus, HeaderCheckItem, HeadersResult } from "../types.js";

function worst(a: CheckStatus, b: CheckStatus): CheckStatus {
  const order: Record<CheckStatus, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
  return order[a] <= order[b] ? a : b;
}

const REFS: Record<string, string> = {
  "Strict-Transport-Security": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
  "Content-Security-Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
  "X-Content-Type-Options": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
  "X-Frame-Options": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
  "Referrer-Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
  "Permissions-Policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
  "X-XSS-Protection": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
};

export function analyzeHeaders(headers: Record<string, string>): HeadersResult {
  const items: HeaderCheckItem[] = [];

  const hsts = headers["strict-transport-security"];
  if (hsts) {
    const hasMaxAge = /max-age=\d+/.test(hsts);
    const parts: string[] = [];
    if (/includeSubDomains/i.test(hsts)) parts.push("includeSubDomains");
    if (/preload/i.test(hsts)) parts.push("preload");
    items.push({ name: "Strict-Transport-Security", present: true, value: hsts, status: hasMaxAge ? "pass" : "warn", explanation: hasMaxAge ? `HSTS enabled${parts.length ? ` with ${parts.join(", ")}` : ""}` : "HSTS present but missing max-age directive", ref: REFS["Strict-Transport-Security"] });
  } else {
    items.push({ name: "Strict-Transport-Security", present: false, value: "missing", status: "fail", explanation: "HSTS not set — browsers may allow insecure connections", ref: REFS["Strict-Transport-Security"] });
  }

  const csp = headers["content-security-policy"];
  items.push(csp
    ? { name: "Content-Security-Policy", present: true, value: csp.length > 80 ? csp.slice(0, 80) + "…" : csp, status: "pass", explanation: "CSP is configured", ref: REFS["Content-Security-Policy"] }
    : { name: "Content-Security-Policy", present: false, value: "missing", status: "warn", explanation: "No CSP — recommended browser-side XSS protection is not configured", ref: REFS["Content-Security-Policy"] }
  );

  const xcto = headers["x-content-type-options"];
  items.push(xcto
    ? { name: "X-Content-Type-Options", present: true, value: xcto, status: xcto.toLowerCase() === "nosniff" ? "pass" : "warn", explanation: xcto.toLowerCase() === "nosniff" ? "MIME sniffing prevented" : `Unexpected value: ${xcto}`, ref: REFS["X-Content-Type-Options"] }
    : { name: "X-Content-Type-Options", present: false, value: "missing", status: "warn", explanation: "Missing — browsers may MIME-sniff responses", ref: REFS["X-Content-Type-Options"] }
  );

  const xfo = headers["x-frame-options"];
  if (xfo) {
    const val = xfo.toUpperCase();
    const ok = val === "DENY" || val === "SAMEORIGIN";
    items.push({ name: "X-Frame-Options", present: true, value: xfo, status: ok ? "pass" : "warn", explanation: ok ? `Clickjacking protection: ${val}` : `Unexpected value: ${xfo}`, ref: REFS["X-Frame-Options"] });
  } else {
    items.push({ name: "X-Frame-Options", present: false, value: "missing", status: "warn", explanation: "Missing — consider using CSP frame-ancestors instead", ref: REFS["X-Frame-Options"] });
  }

  const rp = headers["referrer-policy"];
  items.push(rp
    ? { name: "Referrer-Policy", present: true, value: rp, status: "pass", explanation: `Referrer policy set to ${rp}`, ref: REFS["Referrer-Policy"] }
    : { name: "Referrer-Policy", present: false, value: "missing", status: "warn", explanation: "Missing — browser default referrer behavior applies", ref: REFS["Referrer-Policy"] }
  );

  const pp = headers["permissions-policy"];
  items.push(pp
    ? { name: "Permissions-Policy", present: true, value: pp.length > 80 ? pp.slice(0, 80) + "…" : pp, status: "pass", explanation: "Browser feature permissions restricted", ref: REFS["Permissions-Policy"] }
    // Missing → info, not warn. For typical sites (not embedded as iframe,
    // no use of camera/mic/geo), this header has little real impact — it's a
    // nice-to-have hardening, not a security gap.
    : { name: "Permissions-Policy", present: false, value: "missing", status: "info", explanation: "Missing — browser features not explicitly restricted (low impact for most sites)", ref: REFS["Permissions-Policy"] }
  );

  const xxss = headers["x-xss-protection"];
  if (xxss) {
    items.push({ name: "X-XSS-Protection", present: true, value: xxss, status: "warn", explanation: "Deprecated header — can introduce vulnerabilities in older browsers", ref: REFS["X-XSS-Protection"] });
  } else {
    items.push({ name: "X-XSS-Protection", present: false, value: "not set", status: "pass", explanation: "Correctly absent — this header is deprecated", ref: REFS["X-XSS-Protection"] });
  }

  // Sort: fail first, then warn, then pass
  const order: Record<CheckStatus, number> = { fail: 0, warn: 1, info: 2, pass: 3 };
  items.sort((a, b) => order[a.status] - order[b.status]);

  const overall = items.reduce<CheckStatus>((acc, item) => worst(acc, item.status), "pass");
  return { status: overall, items };
}
