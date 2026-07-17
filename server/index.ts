// MUST be first: loads .env before any env-reading module is evaluated.
import "./loadEnv.js";

import path from "node:path";
import express from "express";
import cors from "cors";
import compression from "compression";
import cookieParser from "cookie-parser";
import { fileURLToPath } from "node:url";
import { rateLimiter } from "./middleware/rateLimit.js";
import { validateRequest } from "./middleware/validateRequest.js";
import { requestLogger } from "./middleware/requestLogger.js";
import fetchRoute from "./routes/fetch.js";
import { createDomainCheckRoutes } from "./routes/domainCheck.js";
import { initDatabase } from "./db.js";
import { createAuth } from "./auth.js";
import { syncAdminEmails } from "./auth.js";
import { createAuthMiddleware, requireAdmin } from "./middleware/authMiddleware.js";
import { createAuthRoutes } from "./routes/auth.js";
import { createScansRoutes } from "./routes/scans.js";
import { createBatchRoutes } from "./routes/batch.js";
import { createWebhooksRoutes } from "./routes/webhooks.js";
import { createReportsRoutes } from "./routes/reports.js";
import { createAdminRoutes } from "./routes/admin.js";
import { createMonitoringRoutes } from "./routes/monitoring.js";
import { createExportRoutes } from "./routes/export.js";
import { createVerifyRoutes } from "./routes/verify.js";
import { ctLogsReady } from "./checkers/knownCtLogs.js";
import { closeCrtShPgPool } from "./checkers/crtShPg.js";
import { initCache, consumeCacheStatsWindow } from "./lib/cache.js";
import { collectWindow as collectMetricsWindow } from "./lib/metrics.js";
import { MonitoringService, QUEUE_NAME } from "./monitoringService.js";
import { AlertDispatcher } from "./alertDispatcher.js";
import { createMonitoringWorker } from "./monitoringWorker.js";
import {
  MAINTENANCE_QUEUE_NAME,
  createMaintenanceWorker,
  scheduleCleanupJob,
  enqueueImmediateCleanup,
  runMaintenanceCleanup,
} from "./maintenanceWorker.js";
import { createLogger } from "./lib/logger.js";

const log = createLogger("server");
const monitoringLog = createLogger("monitoring");

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProduction = process.env.NODE_ENV === "production";

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;

// Behind Cloudflare in production: trust exactly one proxy hop so req.ip and the
// rate limiter use the real client IP from X-Forwarded-For (not Cloudflare's edge
// IP). Safe because the origin firewall only admits Cloudflare's IP ranges.
if (isProduction) {
  app.set("trust proxy", 1);
}

// ── Initialize SQLite database ──
const db = initDatabase();

// ── Sync admin emails from env ──
syncAdminEmails(db);

// ── Set up Lucia Auth ──
const { lucia, google, github } = createAuth(db);

// ── Gzip/brotli compression for all responses ──
// SSE streams must NOT be compressed — gzip buffers writes until flush, which
// defeats the whole point of incremental events. The scan pipeline emits
// `event: section` as soon as each check completes, and the browser must see
// those bytes immediately to render incrementally.
app.use(
  compression({
    filter: (req, res) => {
      if (req.path === "/api/domain-check/stream") return false;
      return compression.filter(req, res);
    },
  }),
);

// ── CORS — needed in dev for cross-origin cookie support ──
if (!isProduction) {
  app.use(
    cors({
      origin: process.env.CORS_ORIGIN || "http://localhost:5173",
      credentials: true,
      exposedHeaders: ["X-Cache-Age-Ms"],
    })
  );
}

// ── Parse cookies (needed for OAuth state cookies and session cookies) ──
app.use(cookieParser());

// ── Parse JSON bodies for POST/PUT/PATCH ──
app.use(express.json());

// ── Security headers ──
// CSP for the production HTML we serve. Notes on the non-obvious directives:
//   img-src ... https:   — OAuth avatars come from Google/GitHub CDNs (NavBar).
//   style-src 'unsafe-inline' — server-rendered /verify and report pages use
//                               inline <style> blocks and style="" attributes.
//   script-src 'self'     — the SPA bundle is an external /assets/*.js module;
//                           the only inline <script> is JSON-LD, which is data
//                           and exempt from CSP. No 'unsafe-inline' needed.
//   frame-ancestors 'none' — modern equivalent of X-Frame-Options: DENY.
const CSP = [
  "default-src 'self'",
  "base-uri 'self'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "img-src 'self' data: https:",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "font-src 'self'",
  "connect-src 'self'",
  "form-action 'self'",
].join("; ");

app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Permissions-Policy",
    "camera=(), microphone=(), geolocation=(), browsing-topics=()",
  );
  // HSTS + CSP only in production. In dev, Express serves just /api (the SPA
  // runs under Vite on :5173) — HSTS would wrongly pin localhost to HTTPS and a
  // strict CSP would break Vite HMR. Browser↔Cloudflare is HTTPS, so HSTS is
  // safe here even though the CF→origin hop is Flexible (plaintext).
  if (isProduction) {
    res.setHeader(
      "Strict-Transport-Security",
      "max-age=31536000; includeSubDomains",
    );
    res.setHeader("Content-Security-Policy", CSP);
  }
  next();
});

// ── Auth middleware (non-blocking — attaches user if present) ──
app.use(createAuthMiddleware(lucia));

// ── Request logging (after auth so we get userId, before routes) ──
app.use(requestLogger);

// ── Rate limiting on API routes ──
app.use("/api", rateLimiter);

// ── Auth routes (OAuth, logout, me) ──
app.use("/api/auth", createAuthRoutes({ lucia, google, github, db }));

// ── Existing routes ──
app.use("/api/fetch", validateRequest, fetchRoute);
app.use("/api/domain-check", validateRequest, createDomainCheckRoutes({ db }));

// ── New API routes ──
app.use("/api/scans", createScansRoutes({ db, lucia }));
app.use("/api/batch", createBatchRoutes({ db, lucia }));
app.use("/api/webhooks", createWebhooksRoutes({ db, lucia }));
app.use("/api/reports", createReportsRoutes({ db }));
app.use("/api/admin", createAdminRoutes({ db }));

// Report export — CT logs and full scan payloads can exceed the default 100kb json limit.
app.use("/api/export", express.json({ limit: "2mb" }), createExportRoutes());

// Public verification page — must register BEFORE the SPA catch-all in
// production so /verify/:scanId returns server-rendered HTML, not index.html.
app.use("/verify", createVerifyRoutes({ db }));

// ── Redis / BullMQ / Monitoring ──
let monitoringService: MonitoringService;

const redisUrl = process.env.REDIS_URL || "redis://localhost:6379";
const IORedis = (await import("ioredis")).default;
const { Queue } = await import("bullmq");

// Stop retrying after the initial connect fails — flips to true in the catch
// block so the retry strategy can short-circuit instead of looping forever.
let redisInitFailed = false;
const redisConnection = new IORedis(redisUrl, {
  maxRetriesPerRequest: null,
  enableReadyCheck: true,
  retryStrategy: (times: number) => {
    if (redisInitFailed) return null; // give up after initial failure
    return Math.min(times * 1000, 30000);
  },
  lazyConnect: true,
});

// Always have an error handler — otherwise EventEmitter logs
// "Unhandled error event" and dumps a stack trace per retry.
let lastRedisErrorAt = 0;
redisConnection.on("error", (err) => {
  const now = Date.now();
  if (now - lastRedisErrorAt > 60_000) {
    monitoringLog.warn({ err: (err as Error).message }, "Redis connection error");
    lastRedisErrorAt = now;
  }
});

try {
  await redisConnection.connect();
  await redisConnection.ping();

  // Wire the shared TTL cache to Redis. Falls back to no-op cache if this never runs.
  initCache(redisConnection);

  const monitoringQueue = new Queue(QUEUE_NAME, { connection: redisConnection });
  const maintenanceQueue = new Queue(MAINTENANCE_QUEUE_NAME, { connection: redisConnection });
  const alertDispatcher = new AlertDispatcher(db);
  monitoringService = new MonitoringService(db, monitoringQueue);

  // Create workers
  await createMonitoringWorker(redisConnection, db, alertDispatcher);
  await createMaintenanceWorker(redisConnection, db);
  await scheduleCleanupJob(maintenanceQueue);
  // Drain any backlog accumulated since last run — runs in the worker, not here.
  await enqueueImmediateCleanup(maintenanceQueue);

  // Bull-board dashboard (admin only, at /admin/queues)
  try {
    const { createBullBoard } = await import("@bull-board/api");
    const { BullMQAdapter } = await import("@bull-board/api/bullMQAdapter");
    const { ExpressAdapter } = await import("@bull-board/express");
    const serverAdapter = new ExpressAdapter();
    serverAdapter.setBasePath("/admin/queues");
    createBullBoard({
      queues: [new BullMQAdapter(monitoringQueue), new BullMQAdapter(maintenanceQueue)],
      serverAdapter,
    });
    app.use("/admin/queues", isProduction ? requireAdmin : (_r: any, _s: any, n: any) => n(), serverAdapter.getRouter());
    monitoringLog.info("Bull-board dashboard available at /admin/queues");
  } catch (e) {
    monitoringLog.warn({ err: (e as Error).message }, "Bull-board setup failed");
  }

  // Restore jobs
  const restored = await monitoringService.restoreJobs();
  if (restored > 0) monitoringLog.info({ restored }, "restored repeatable jobs");

  // Restore pending alert aggregation timers (and re-fire any unsent criticals)
  await alertDispatcher.restorePending();

  monitoringLog.info("Redis connected, monitoring enabled");
} catch (err) {
  redisInitFailed = true;
  redisConnection.disconnect();
  const installHint = process.platform === "win32"
    ? "docker run -d -p 6379:6379 redis  (or install Memurai / use WSL)"
    : process.platform === "darwin"
      ? "brew install redis && brew services start redis"
      : "sudo apt install redis-server";
  monitoringLog.warn(
    { installHint, err: (err as Error).message },
    "Redis unavailable — monitoring disabled"
  );
  monitoringService = new MonitoringService(db, null);
}

app.use("/api/monitoring", createMonitoringRoutes({ monitoringService }));

// ── In production, serve the built frontend ──
if (isProduction) {
  const distPath = path.resolve(__dirname, "..", "dist");
  app.use(express.static(distPath, { maxAge: "1y", immutable: true }));
  // index.html should not be cached aggressively
  app.get("*", (_req, res) => {
    res.setHeader("Cache-Control", "no-cache");
    res.sendFile(path.join(distPath, "index.html"));
  });
}

// Wait for CT log registry before accepting requests
await ctLogsReady;

app.listen(PORT, () => {
  log.info({ port: PORT, env: isProduction ? "production" : "development" }, "server listening");
  // Fallback for the Redis-down case: the daily BullMQ job won't fire and we
  // didn't enqueue an immediate one, so do a chunked cleanup directly here.
  // Runs after listen() so it never blocks accepting requests; chunks yield
  // to the event loop between deletes.
  if (redisInitFailed) {
    runMaintenanceCleanup(db).catch((err) =>
      createLogger("startup").error({ err }, "fallback maintenance cleanup failed"),
    );
  }
});

// ── Cache metrics → Axiom ──
// Emit a per-interval delta of cache hits/misses as a structured log line. The
// pino transport ships it to Axiom in production, where it can be aggregated by
// `keyType` / charted as a hit rate. Skips empty windows so idle periods don't
// spam the dataset. `.unref()` so this timer never keeps the process alive.
// Production-only for now — Axiom is the only consumer, so there's nothing to
// emit in dev.
const metricsLog = createLogger("metrics");
const CACHE_METRICS_INTERVAL_MS = 60 * 60_000; // hourly
const cacheMetricsTimer = isProduction
  ? setInterval(() => {
      const window = consumeCacheStatsWindow();
      if (window) metricsLog.info({ cache: window }, "cache metrics");
      // App metrics: one flat line per (metric, label-set) for easy APL aggregation.
      for (const line of collectMetricsWindow()) metricsLog.info(line, "metric");
    }, CACHE_METRICS_INTERVAL_MS)
  : null;
cacheMetricsTimer?.unref();

// ── Graceful shutdown ──
// Close the crt.sh Postgres pool so in-flight connections drain cleanly on
// SIGTERM (systemd stop / redeploy) and SIGINT (Ctrl-C in dev).
let shuttingDown = false;
async function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  log.info({ signal }, "shutting down");
  if (cacheMetricsTimer) clearInterval(cacheMetricsTimer);
  await closeCrtShPgPool().catch((err) => log.warn({ err: (err as Error).message }, "crt.sh pg pool close failed"));
  process.exit(0);
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));

export default app;
