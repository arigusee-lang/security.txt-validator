/**
 * Lightweight in-process metrics.
 *
 * Same model as the cache counters in cache.ts, generalised: counters (with
 * labels) and timers (count/sum/max). Single-process server — scan pipeline,
 * HTTP routes and the monitoring/maintenance workers all share this module, so
 * plain module-level state captures everything.
 *
 * Each cell keeps two accumulators:
 *   - `tot*` — cumulative since process start, backs the admin endpoint.
 *   - `win*` — current window, reset by `collectWindow()` each time the hourly
 *     emitter ships a sample to Axiom (via the pino transport).
 *
 * Window samples are emitted one flat log line per (metric, label-set) so they
 * aggregate cleanly in APL, e.g.
 *   where metric == "scan" | summarize sum(count) by outcome
 */

type Labels = Record<string, string>;

interface CounterCell {
  win: number;
  tot: number;
}

interface TimerCell {
  winCount: number;
  winSum: number;
  winMax: number;
  totCount: number;
  totSum: number;
  totMax: number;
}

const counters = new Map<string, Map<string, CounterCell>>();
const timers = new Map<string, Map<string, TimerCell>>();

/** Deterministic key for a label set: `a=1,b=2` (sorted). Empty string = no labels. */
function labelKey(labels?: Labels): string {
  if (!labels) return "";
  return Object.keys(labels)
    .sort()
    .map((k) => `${k}=${labels[k]}`)
    .join(",");
}

/** Inverse of labelKey — back to a flat object for the log line / endpoint. */
function parseLabels(key: string): Labels {
  if (!key) return {};
  const out: Labels = {};
  for (const part of key.split(",")) {
    const eq = part.indexOf("=");
    if (eq > 0) out[part.slice(0, eq)] = part.slice(eq + 1);
  }
  return out;
}

/** Increment a counter. */
export function incr(name: string, labels?: Labels, n = 1): void {
  let m = counters.get(name);
  if (!m) {
    m = new Map();
    counters.set(name, m);
  }
  const k = labelKey(labels);
  const cell = m.get(k);
  if (cell) {
    cell.win += n;
    cell.tot += n;
  } else {
    m.set(k, { win: n, tot: n });
  }
}

/** Record a duration/value sample (ms). */
export function observe(name: string, valueMs: number, labels?: Labels): void {
  let m = timers.get(name);
  if (!m) {
    m = new Map();
    timers.set(name, m);
  }
  const k = labelKey(labels);
  const cell = m.get(k);
  if (cell) {
    cell.winCount++;
    cell.winSum += valueMs;
    if (valueMs > cell.winMax) cell.winMax = valueMs;
    cell.totCount++;
    cell.totSum += valueMs;
    if (valueMs > cell.totMax) cell.totMax = valueMs;
  } else {
    m.set(k, { winCount: 1, winSum: valueMs, winMax: valueMs, totCount: 1, totSum: valueMs, totMax: valueMs });
  }
}

/**
 * Drain the current window into flat log-line objects and reset window
 * accumulators. Cumulative totals are left intact for the admin endpoint.
 * Cells with no activity this window are skipped.
 */
export function collectWindow(): Array<Record<string, unknown>> {
  const lines: Array<Record<string, unknown>> = [];

  for (const [name, m] of counters) {
    for (const [k, cell] of m) {
      if (cell.win === 0) continue;
      lines.push({ metric: name, ...parseLabels(k), count: cell.win });
      cell.win = 0;
    }
  }

  for (const [name, m] of timers) {
    for (const [k, cell] of m) {
      if (cell.winCount === 0) continue;
      lines.push({
        metric: name,
        ...parseLabels(k),
        count: cell.winCount,
        avgMs: Math.round(cell.winSum / cell.winCount),
        maxMs: cell.winMax,
      });
      cell.winCount = 0;
      cell.winSum = 0;
      cell.winMax = 0;
    }
  }

  return lines;
}

export interface MetricsSnapshot {
  counters: Record<string, Record<string, number>>;
  timers: Record<string, Record<string, { count: number; avgMs: number; maxMs: number }>>;
}

/** Cumulative snapshot for the admin endpoint. Label sets keyed by `a=1,b=2`. */
export function getMetrics(): MetricsSnapshot {
  const out: MetricsSnapshot = { counters: {}, timers: {} };
  for (const [name, m] of counters) {
    const byLabel: Record<string, number> = {};
    for (const [k, cell] of m) byLabel[k || "_"] = cell.tot;
    out.counters[name] = byLabel;
  }
  for (const [name, m] of timers) {
    const byLabel: Record<string, { count: number; avgMs: number; maxMs: number }> = {};
    for (const [k, cell] of m) {
      byLabel[k || "_"] = {
        count: cell.totCount,
        avgMs: cell.totCount > 0 ? Math.round(cell.totSum / cell.totCount) : 0,
        maxMs: cell.totMax,
      };
    }
    out.timers[name] = byLabel;
  }
  return out;
}

/** Reset all counters and timers. */
export function resetMetrics(): void {
  counters.clear();
  timers.clear();
}
