/**
 * Redis-backed TTL cache.
 *
 * Two-window model: every entry has a `freshUntil` timestamp (the primary TTL)
 * and the Redis key itself lives until `staleUntil` (optional, longer). Normal
 * reads return null past `freshUntil`; `cacheGetMaybeStale()` returns the value
 * regardless and flags it as stale — useful for "fall back to last known good
 * result when upstream is down."
 *
 * Falls back to no-op when Redis is unreachable or `initCache` was never called
 * with a live connection — callers just see misses and the system stays hot.
 */
import type { Redis } from "ioredis";

interface CacheEnvelope<T> {
  data: T;
  setAt: number;
  freshUntil: number;
}

let client: Redis | null = null;
let prefix = "cache:";

const DEFAULT_FRESH_TTL_MS = 5 * 60 * 1000;

// ── Hit/miss metrics ──────────────────────────────────────────────────────
// In-process counters for cache effectiveness. Single-process server (scan
// pipeline + monitoring/maintenance workers all share this module), so plain
// module-level state captures every read. Only the normal fresh-read paths
// (cacheGet / cacheGetWithAge) are counted — `cacheGetMaybeStale` is a fallback
// path with different semantics and is excluded. Reads while Redis is down are
// not counted at all, so the hit rate stays meaningful when caching is disabled.
interface CacheCounter {
  hits: number;
  misses: number;
}

const totals: CacheCounter = { hits: 0, misses: 0 };
const byType = new Map<string, CacheCounter>();

/** Cache keys are `<type>:<rest>` (e.g. `spf:example.com`, `ct:example.com:pg:s0`). */
function keyType(key: string): string {
  const i = key.indexOf(":");
  return i === -1 ? key : key.slice(0, i);
}

function record(key: string, hit: boolean): void {
  if (hit) totals.hits++;
  else totals.misses++;
  const t = keyType(key);
  let c = byType.get(t);
  if (!c) {
    c = { hits: 0, misses: 0 };
    byType.set(t, c);
  }
  if (hit) c.hits++;
  else c.misses++;
}

function withRate(c: CacheCounter): CacheCounter & { total: number; hitRate: number } {
  const total = c.hits + c.misses;
  return { ...c, total, hitRate: total > 0 ? c.hits / total : 0 };
}

export interface CacheStats {
  hits: number;
  misses: number;
  total: number;
  hitRate: number;
  enabled: boolean;
  byType: Record<string, CacheCounter & { total: number; hitRate: number }>;
}

/** Snapshot of cache hit/miss counters since process start (or last reset). */
export function getCacheStats(): CacheStats {
  return {
    ...withRate(totals),
    enabled: ready() !== null,
    byType: Object.fromEntries(
      [...byType.entries()]
        .map(([t, c]) => [t, withRate(c)] as const)
        .sort((a, b) => b[1].total - a[1].total),
    ),
  };
}

/** Reset all hit/miss counters. */
export function resetCacheStats(): void {
  totals.hits = 0;
  totals.misses = 0;
  byType.clear();
  lastTotals = { hits: 0, misses: 0 };
  lastByType.clear();
}

// ── Windowed deltas for log-based metrics (Axiom) ──────────────────────────
// The cumulative counters above back the admin endpoint. For Axiom we instead
// emit a per-interval delta: counts since the previous emit. That makes the
// log line a discrete sample (easy to sum / rate in APL) instead of an
// ever-growing cumulative number.
let lastTotals: CacheCounter = { hits: 0, misses: 0 };
const lastByType = new Map<string, CacheCounter>();

/**
 * Return cache hit/miss counts since the last call, then mark the current
 * cumulative totals as the new baseline. Returns null when nothing happened
 * in the window so callers can skip emitting an empty log line.
 */
export function consumeCacheStatsWindow(): CacheStats | null {
  const dHits = totals.hits - lastTotals.hits;
  const dMisses = totals.misses - lastTotals.misses;
  if (dHits === 0 && dMisses === 0) return null;

  const byTypeDelta: Record<string, CacheCounter & { total: number; hitRate: number }> = {};
  for (const [t, c] of byType) {
    const prev = lastByType.get(t) ?? { hits: 0, misses: 0 };
    const dh = c.hits - prev.hits;
    const dm = c.misses - prev.misses;
    if (dh === 0 && dm === 0) continue;
    byTypeDelta[t] = withRate({ hits: dh, misses: dm });
    lastByType.set(t, { hits: c.hits, misses: c.misses });
  }

  lastTotals = { hits: totals.hits, misses: totals.misses };

  return {
    ...withRate({ hits: dHits, misses: dMisses }),
    enabled: ready() !== null,
    byType: byTypeDelta,
  };
}

export function initCache(redis: Redis | null, options?: { prefix?: string }): void {
  client = redis;
  if (options?.prefix !== undefined) prefix = options.prefix;
}

function ready(): Redis | null {
  if (!client) return null;
  if (client.status !== "ready") return null;
  return client;
}

// Some cached payloads contain Node Buffers (e.g. raw TLS cert bytes for SCT
// parsing). Plain JSON.stringify turns those into `{type:"Buffer",data:[...]}`
// that JSON.parse cannot round-trip back to a real Buffer — callers would lose
// methods like `.indexOf` / `.readUInt16BE`. The replacer/reviver below tag
// Buffers with `{__b:<base64>}` so we get them back as real Buffer instances.
function replacer(_key: string, value: unknown): unknown {
  if (value && typeof value === "object" && (value as any).type === "Buffer" && Array.isArray((value as any).data)) {
    return { __b: Buffer.from((value as any).data).toString("base64") };
  }
  if (Buffer.isBuffer(value)) {
    return { __b: value.toString("base64") };
  }
  return value;
}

function reviver(_key: string, value: unknown): unknown {
  if (value && typeof value === "object" && typeof (value as any).__b === "string" && Object.keys(value as any).length === 1) {
    return Buffer.from((value as any).__b, "base64");
  }
  return value;
}

function parse<T>(raw: string | null): CacheEnvelope<T> | null {
  if (!raw) return null;
  try {
    return JSON.parse(raw, reviver) as CacheEnvelope<T>;
  } catch {
    return null;
  }
}

export async function cacheGet<T>(key: string): Promise<T | null> {
  const r = ready();
  if (!r) return null;
  try {
    const env = parse<T>(await r.get(prefix + key));
    if (!env || Date.now() > env.freshUntil) {
      record(key, false);
      return null;
    }
    record(key, true);
    return env.data;
  } catch {
    record(key, false);
    return null;
  }
}

/** Like cacheGet, but also returns the entry's age in ms. Returns null on miss or stale. */
export async function cacheGetWithAge<T>(key: string): Promise<{ data: T; ageMs: number } | null> {
  const r = ready();
  if (!r) return null;
  try {
    const env = parse<T>(await r.get(prefix + key));
    const now = Date.now();
    if (!env || now > env.freshUntil) {
      record(key, false);
      return null;
    }
    record(key, true);
    return { data: env.data, ageMs: now - env.setAt };
  } catch {
    record(key, false);
    return null;
  }
}

/**
 * Read the cache entry whether fresh or stale. Use when upstream failed and you
 * want last-known-good data. `isStale` is true past the freshness window.
 */
export async function cacheGetMaybeStale<T>(
  key: string,
): Promise<{ data: T; ageMs: number; isStale: boolean } | null> {
  const r = ready();
  if (!r) return null;
  try {
    const env = parse<T>(await r.get(prefix + key));
    if (!env) return null;
    const now = Date.now();
    return { data: env.data, ageMs: now - env.setAt, isStale: now > env.freshUntil };
  } catch {
    return null;
  }
}

/**
 * Store a value. `freshTtlMs` is how long it stays "fresh" (visible to
 * cacheGet/cacheGetWithAge). If `staleTtlMs` is provided and larger, the key
 * lives longer in Redis and remains accessible via cacheGetMaybeStale — letting
 * callers degrade gracefully when upstream is down.
 */
export async function cacheSet<T>(
  key: string,
  data: T,
  freshTtlMs: number = DEFAULT_FRESH_TTL_MS,
  staleTtlMs?: number,
): Promise<void> {
  const r = ready();
  if (!r) return;
  try {
    const setAt = Date.now();
    const envelope: CacheEnvelope<T> = {
      data,
      setAt,
      freshUntil: setAt + freshTtlMs,
    };
    const totalTtlMs = Math.max(freshTtlMs, staleTtlMs ?? freshTtlMs);
    await r.set(prefix + key, JSON.stringify(envelope, replacer), "PX", totalTtlMs);
  } catch {
    // best-effort — cache failures must never break the request
  }
}
