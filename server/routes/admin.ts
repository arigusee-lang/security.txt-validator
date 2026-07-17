import { Router } from "express";
import crypto from "node:crypto";
import type Database from "better-sqlite3";
import { requireAuth, requireAdmin } from "../middleware/authMiddleware.js";
import { getCacheStats, resetCacheStats } from "../lib/cache.js";
import { getMetrics, resetMetrics } from "../lib/metrics.js";

interface AdminDeps {
  db: Database.Database;
}

const VALID_PLANS = ["free", "premium", "premium_plus"] as const;

export function createAdminRoutes({ db }: AdminDeps): Router {
  const router = Router();
  router.use(requireAuth, requireAdmin);

  // GET /api/admin/users — paginated user list with search and plan filter
  router.get("/users", (req, res) => {
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 20));
    const offset = (page - 1) * limit;
    const search = (req.query.search as string) || "";
    const plan = (req.query.plan as string) || "";

    let where = "1=1";
    const params: unknown[] = [];

    if (search) {
      where += " AND (LOWER(email) LIKE ? OR LOWER(name) LIKE ?)";
      const term = `%${search.toLowerCase()}%`;
      params.push(term, term);
    }
    if (plan) {
      where += " AND plan = ?";
      params.push(plan);
    }

    const total = (
      db.prepare(`SELECT COUNT(*) as cnt FROM users WHERE ${where}`).get(...params) as { cnt: number }
    ).cnt;

    const users = db
      .prepare(
        `SELECT id, email, name, provider, plan, role, created_at, last_login_at
         FROM users WHERE ${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
      .all(...params, limit, offset);

    res.json({ users, total, page, limit });
  });

  // GET /api/admin/stats — user statistics
  router.get("/stats", (_req, res) => {
    const rows = db
      .prepare("SELECT plan, COUNT(*) as cnt FROM users GROUP BY plan")
      .all() as Array<{ plan: string; cnt: number }>;

    const byPlan: Record<string, number> = { free: 0, premium: 0, premium_plus: 0 };
    let total = 0;
    for (const row of rows) {
      byPlan[row.plan] = row.cnt;
      total += row.cnt;
    }

    res.json({ total, byPlan });
  });

  // GET /api/admin/cache-stats — cache hit/miss counters since process start
  router.get("/cache-stats", (_req, res) => {
    res.json(getCacheStats());
  });

  // POST /api/admin/cache-stats/reset — zero the counters
  router.post("/cache-stats/reset", (_req, res) => {
    resetCacheStats();
    res.json(getCacheStats());
  });

  // GET /api/admin/metrics — cumulative app metrics (scans, checks, CT sources, jobs)
  router.get("/metrics", (_req, res) => {
    res.json(getMetrics());
  });

  // POST /api/admin/metrics/reset — zero all app metrics
  router.post("/metrics/reset", (_req, res) => {
    resetMetrics();
    res.json(getMetrics());
  });

  // PATCH /api/admin/users/:id/plan — change user plan
  router.patch("/users/:id/plan", (req, res) => {
    const { id } = req.params;
    const { plan } = req.body;

    if (!plan || !VALID_PLANS.includes(plan)) {
      res.status(400).json({
        error: "invalid_plan",
        message: "Plan must be one of: free, premium, premium_plus",
      });
      return;
    }

    const user = db
      .prepare("SELECT id, email, name, provider, plan, role, created_at, last_login_at FROM users WHERE id = ?")
      .get(id) as Record<string, unknown> | undefined;

    if (!user) {
      res.status(404).json({ error: "user_not_found" });
      return;
    }

    const oldPlan = user.plan as string;
    if (oldPlan === plan) {
      res.json(user);
      return;
    }

    db.prepare("UPDATE users SET plan = ? WHERE id = ?").run(plan, id);

    // Audit log
    db.prepare(
      `INSERT INTO plan_audit_log (id, admin_id, user_id, old_plan, new_plan, changed_at)
       VALUES (?, ?, ?, ?, ?, datetime('now'))`
    ).run(crypto.randomUUID(), req.user!.id, id, oldPlan, plan);

    const updated = db
      .prepare("SELECT id, email, name, provider, plan, role, created_at, last_login_at FROM users WHERE id = ?")
      .get(id);

    res.json(updated);
  });

  // GET /api/admin/users/:id/scans — user scan history
  router.get("/users/:id/scans", (req, res) => {
    const { id } = req.params;
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 20));
    const offset = (page - 1) * limit;

    const user = db.prepare("SELECT id FROM users WHERE id = ?").get(id);
    if (!user) {
      res.status(404).json({ error: "user_not_found" });
      return;
    }

    const total = (
      db.prepare("SELECT COUNT(*) as cnt FROM scans WHERE user_id = ?").get(id) as { cnt: number }
    ).cnt;

    const scans = db
      .prepare(
        `SELECT id, domain, scan_type, status, score, created_at, completed_at
         FROM scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
      )
      .all(id, limit, offset);

    res.json({ scans, total, page, limit });
  });

  // GET /api/admin/audit-log — paginated audit log
  router.get("/audit-log", (req, res) => {
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 20));
    const offset = (page - 1) * limit;

    const total = (
      db.prepare("SELECT COUNT(*) as cnt FROM plan_audit_log").get() as { cnt: number }
    ).cnt;

    const entries = db
      .prepare(
        `SELECT a.id, a.admin_id, adm.email as admin_email,
                a.user_id, u.email as user_email,
                a.old_plan, a.new_plan, a.changed_at
         FROM plan_audit_log a
         LEFT JOIN users adm ON adm.id = a.admin_id
         LEFT JOIN users u ON u.id = a.user_id
         ORDER BY a.changed_at DESC LIMIT ? OFFSET ?`
      )
      .all(limit, offset);

    res.json({ entries, total, page, limit });
  });

  // GET /api/admin/users/:id/notifications — user notification log
  router.get("/users/:id/notifications", (req, res) => {
    const { id } = req.params;
    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 20));
    const offset = (page - 1) * limit;

    const user = db.prepare("SELECT id FROM users WHERE id = ?").get(id);
    if (!user) {
      res.status(404).json({ error: "user_not_found" });
      return;
    }

    const total = (
      db.prepare("SELECT COUNT(*) as cnt FROM notification_log WHERE user_id = ?").get(id) as { cnt: number }
    ).cnt;

    const notifications = db
      .prepare(
        `SELECT n.id, n.type, n.status, n.error, n.created_at, n.sent_at,
                s.domain
         FROM notification_log n
         LEFT JOIN scans s ON s.id = n.scan_id
         WHERE n.user_id = ?
         ORDER BY n.created_at DESC LIMIT ? OFFSET ?`
      )
      .all(id, limit, offset);

    res.json({ notifications, total, page, limit });
  });

  // GET /api/admin/users/:id/monitored-domains — user monitored domains
  router.get("/users/:id/monitored-domains", (req, res) => {
    const { id } = req.params;

    const user = db.prepare("SELECT id FROM users WHERE id = ?").get(id);
    if (!user) {
      res.status(404).json({ error: "user_not_found" });
      return;
    }

    const domains = db.prepare(`
      SELECT md.id, md.domain, md.enabled, md.created_at,
        (SELECT COUNT(*) FROM monitors m WHERE m.domain_id = md.id) as monitors_count,
        (SELECT COUNT(*) FROM monitor_alerts ma WHERE ma.domain_id = md.id AND ma.created_at > datetime('now', '-24 hours')) as alerts_count
      FROM monitored_domains md
      WHERE md.user_id = ?
      ORDER BY md.created_at DESC
    `).all(id);

    res.json({ domains });
  });

  return router;
}
