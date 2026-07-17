const API = "/api/domain-check";

interface GetResult {
  data: any;
  cacheAgeMs: number | null;
}

async function get(
  path: string,
  domain: string,
  noCache: boolean,
  timeoutMs: number,
  scanId?: string,
  extra?: string,
): Promise<GetResult | null> {
  const nc = noCache ? "&noCache=1" : "";
  const sid = scanId ? `&scanId=${scanId}` : "";
  const ex = extra || "";
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(
      `${API}/${path}?domain=${encodeURIComponent(domain)}${nc}${sid}${ex}`,
      { signal: controller.signal, credentials: "include" },
    );
    if (!res.ok) {
      const errBody = await res.json().catch(() => null);
      throw new Error(errBody?.message || `HTTP ${res.status}`);
    }
    const ageHeader = res.headers.get("X-Cache-Age-Ms");
    const cacheAgeMs = ageHeader !== null ? parseInt(ageHeader, 10) : null;
    return { data: await res.json(), cacheAgeMs: Number.isFinite(cacheAgeMs as number) ? cacheAgeMs : null };
  } catch (err: any) {
    if (err.name === "AbortError") return null;
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export interface CheckGroup {
  key: string;
  promise: Promise<GetResult | null>;
}

export function runAllChecks(
  domain: string,
  noCache: boolean,
  onResult: (key: string, data: any, cacheAgeMs: number | null) => void,
  onError: (key: string, err: any) => void,
  scanId?: string,
  ctSource?: import("./types").CtSourcePref,
): Promise<void> {
  const ctExtra = ctSource ? `&ctSource=${encodeURIComponent(ctSource)}` : "";
  const groups: CheckGroup[] = [
    { key: "dns", promise: get("dns", domain, noCache, 20000, scanId) },
    { key: "web", promise: get("web", domain, noCache, 30000, scanId) },
    { key: "http", promise: get("http", domain, noCache, 25000, scanId) },
    { key: "external", promise: get("external", domain, noCache, 50000, scanId, ctExtra) },
  ];

  const all = groups.map(g =>
    g.promise
      .then(result => {
        if (result) onResult(g.key, result.data, result.cacheAgeMs);
        else onError(g.key, new Error("Request timed out"));
      })
      .catch(err => onError(g.key, err))
  );

  return Promise.allSettled(all).then(() => {});
}
