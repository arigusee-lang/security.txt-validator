/**
 * SSE client for the wave-based scan pipeline.
 *
 * Streams individual check results (`section` events) as they complete on the
 * server, so the UI can render each card the moment its data is ready —
 * without waiting for slow checks (CT logs, WHOIS) to block fast ones.
 *
 * Server side: server/lib/scanPipeline.ts → GET /api/domain-check/stream
 */

export type ScanSection =
  | "infrastructure"
  | "spf"
  | "dmarc"
  | "dkim"
  | "dnssec"
  | "caa"
  | "mx"
  | "ns"
  | "blacklist"
  | "danglingDns"
  | "domainExpiry"
  | "securityTxt"
  | "headers"
  | "ssl"
  | "redirects"
  | "safeBrowsing"
  | "urlhaus"
  | "ctLogs";

export interface ScanStreamHandlers {
  onSection: (section: ScanSection, data: any, cacheAgeMs: number | null) => void;
  onSectionError?: (section: ScanSection, message: string) => void;
  onDone?: () => void;
  onError?: (message: string) => void;
}

export interface ScanStreamOptions {
  noCache?: boolean;
  ctSource?: import("./types").CtSourcePref;
  scanId?: string;
}

/**
 * Start an SSE scan. Returns a `cancel` function that closes the stream.
 * Caller must call cancel when navigating away to avoid leaking connections.
 */
export function runScanStream(
  domain: string,
  opts: ScanStreamOptions,
  handlers: ScanStreamHandlers,
): () => void {
  const params = new URLSearchParams();
  params.set("domain", domain);
  if (opts.noCache) params.set("noCache", "1");
  if (opts.ctSource) params.set("ctSource", opts.ctSource);
  if (opts.scanId) params.set("scanId", opts.scanId);

  const url = `/api/domain-check/stream?${params.toString()}`;
  const source = new EventSource(url, { withCredentials: true });

  let doneReceived = false;

  source.addEventListener("section", (e) => {
    try {
      const payload = JSON.parse((e as MessageEvent).data);
      handlers.onSection(payload.section, payload.data, payload.cacheAgeMs ?? null);
    } catch (err) {
      // Malformed event — log and continue. The stream will end gracefully.
      console.warn("[scan-stream] malformed section payload", err);
    }
  });

  source.addEventListener("section-error", (e) => {
    try {
      const payload = JSON.parse((e as MessageEvent).data);
      handlers.onSectionError?.(payload.section, payload.message ?? "Check failed");
    } catch { /* ignore */ }
  });

  source.addEventListener("done", () => {
    doneReceived = true;
    source.close();
    handlers.onDone?.();
  });

  source.addEventListener("error", () => {
    // EventSource fires 'error' on both real network failures and on the
    // normal close after our 'done' event — filter out the latter.
    if (source.readyState === EventSource.CLOSED && !doneReceived) {
      handlers.onError?.("Connection lost");
    }
  });

  return () => {
    if (!doneReceived) source.close();
  };
}
