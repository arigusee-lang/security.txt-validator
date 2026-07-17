/** Build a flat array of { category, check, status, detail } rows from scan results */
function buildRows(dns: any, web: any, expiry: any, ct: any, redirects: any, reputation: any): { category: string; check: string; status: string; detail: string }[] {
  const rows: { category: string; check: string; status: string; detail: string }[] = [];

  // SSL
  if (web?.ssl) {
    const s = web.ssl;
    rows.push({ category: "SSL/TLS", check: "Certificate", status: s.status, detail: s.error || `${s.issuer} — expires ${s.validTo?.slice(0, 10) || "?"} (${s.daysRemaining ?? "?"}d)` });
  }

  // Security Headers
  if (web?.headers?.items) {
    for (const h of web.headers.items) {
      rows.push({ category: "Headers", check: h.name, status: h.status, detail: h.explanation || h.value || "" });
    }
  }

  // security.txt
  if (web?.securityTxt) {
    const st = web.securityTxt;
    rows.push({ category: "security.txt", check: "Availability", status: st.status, detail: st.available ? `Found at ${st.fetchedFrom || "?"}` : (st.error || "Not found") });
  }

  // Email: SPF, DMARC, DKIM
  if (dns?.spf) rows.push({ category: "Email", check: "SPF", status: dns.spf.status, detail: dns.spf.record || dns.spf.error || "—" });
  if (dns?.dmarc) rows.push({ category: "Email", check: "DMARC", status: dns.dmarc.status, detail: dns.dmarc.record || dns.dmarc.error || "—" });
  if (dns?.dkim) rows.push({ category: "Email", check: "DKIM", status: dns.dkim.status, detail: `${dns.dkim.foundCount}/${dns.dkim.totalChecked} selectors found` });

  // DNS
  if (dns?.dnssec) rows.push({ category: "DNS", check: "DNSSEC", status: dns.dnssec.status, detail: dns.dnssec.enabled ? "Enabled" : (dns.dnssec.error || "Not enabled") });
  if (dns?.caa) rows.push({ category: "DNS", check: "CAA", status: dns.caa.status, detail: dns.caa.records?.length ? dns.caa.records.map((r: any) => `${r.tag} ${r.value}`).join("; ") : (dns.caa.error || "No records") });
  if (dns?.ns) rows.push({ category: "DNS", check: "Nameservers", status: dns.ns.status, detail: dns.ns.nameservers?.join(", ") || dns.ns.error || "—" });
  if (dns?.mx) rows.push({ category: "DNS", check: "MX", status: dns.mx.status, detail: dns.mx.records?.map((r: any) => r.exchange).join(", ") || "—" });

  // Blacklist
  if (dns?.blacklist) {
    const bl = dns.blacklist;
    const listed = bl.providers?.filter((p: any) => p.listed) || [];
    rows.push({ category: "Reputation", check: "Blacklists", status: bl.status, detail: listed.length ? `Listed on: ${listed.map((p: any) => p.provider).join(", ")}` : `Clean (IP: ${bl.ip || "?"})` });
  }

  // Domain Expiry
  if (expiry) {
    rows.push({ category: "DNS", check: "Domain Expiry", status: expiry.status, detail: expiry.expirationDate ? `Expires ${expiry.expirationDate.slice(0, 10)} (${expiry.daysRemaining}d)` : (expiry.error || "—") });
  }

  // Redirects
  if (redirects?.items) {
    for (const r of redirects.items) {
      rows.push({ category: "Redirects", check: r.check, status: r.status, detail: r.detail });
    }
  }

  // Reputation
  if (reputation?.safeBrowsing) rows.push({ category: "Reputation", check: "Safe Browsing", status: reputation.safeBrowsing.status, detail: reputation.safeBrowsing.safe === false ? `Threats: ${reputation.safeBrowsing.threats?.join(", ")}` : "Clean" });
  if (reputation?.urlhaus) rows.push({ category: "Reputation", check: "URLhaus", status: reputation.urlhaus.status, detail: reputation.urlhaus.listed ? `${reputation.urlhaus.urlCount} malicious URLs` : "Clean" });

  // CT Logs
  if (ct) {
    rows.push({ category: "CT Logs", check: "Certificate Transparency", status: ct.status, detail: `${ct.totalCerts} certs found (source: ${ct.source || "?"})` });
    if (ct.findings) {
      for (const f of ct.findings) {
        rows.push({ category: "CT Logs", check: f.title, status: f.severity, detail: f.description });
      }
    }
  }

  return rows;
}

function escapeCsv(val: string): string {
  if (!val) return "";
  if (val.includes(",") || val.includes('"') || val.includes("\n")) {
    return `"${val.replace(/"/g, '""')}"`;
  }
  return val;
}

export function exportCsv(domain: string, dns: any, web: any, expiry: any, ct: any, redirects: any, reputation: any): void {
  const rows = buildRows(dns, web, expiry, ct, redirects, reputation);
  const header = "Category,Check,Status,Detail";
  const lines = rows.map(r => `${escapeCsv(r.category)},${escapeCsv(r.check)},${escapeCsv(r.status)},${escapeCsv(r.detail)}`);
  const csv = [header, ...lines].join("\n");
  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${domain}-security-report.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export interface ReportPayload {
  domain: string;
  scanDate: string;
  score: { total: number; breakdown?: Record<string, { earned: number; max: number }> } | null;
  /** Persisted scan id (only set for saved scans) — drives the verify-URL footer. */
  scanId?: string | null;
  diff?: any;
  dns: any;
  web: any;
  expiry: any;
  ct: any;
  redirects: any;
  reputation: any;
}

async function downloadFromServer(format: "html" | "pdf", payload: ReportPayload): Promise<void> {
  const res = await fetch(`/api/export/${format}`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    let message = `Export failed (${res.status})`;
    try {
      const data = await res.json();
      if (data?.message) message = data.message;
    } catch {
      // non-JSON error body — keep default message
    }
    throw new Error(message);
  }

  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${payload.domain}-security-report.${format}`;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportHtml(payload: ReportPayload): Promise<void> {
  return downloadFromServer("html", payload);
}

export function exportPdf(payload: ReportPayload): Promise<void> {
  return downloadFromServer("pdf", payload);
}
