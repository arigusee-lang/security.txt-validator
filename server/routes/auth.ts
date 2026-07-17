import { Router } from "express";
import * as arctic from "arctic";
import crypto from "node:crypto";
import type { Lucia } from "lucia";
import type Database from "better-sqlite3";
import { requireAuth } from "../middleware/authMiddleware.js";
import { createLogger } from "../lib/logger.js";

const googleLog = createLogger("auth/google");
const githubLog = createLogger("auth/github");

/** In dev, redirect to Vite dev server; in prod, redirect to same origin */
const FRONTEND_URL = process.env.APP_URL || "http://localhost:5173";
function frontendRedirect(path: string): string {
  return `${FRONTEND_URL}${path}`;
}

interface AuthDeps {
  lucia: Lucia;
  google: InstanceType<typeof arctic.Google> | null;
  github: InstanceType<typeof arctic.GitHub> | null;
  db: Database.Database;
}

export function createAuthRoutes({ lucia, google, github, db }: AuthDeps): Router {
  const router = Router();

  // ── Google OAuth ──

  router.get("/google", async (_req, res) => {
    if (!google) { res.redirect(frontendRedirect("/?auth_error=not_configured")); return; }
    try {
      const state = arctic.generateState();
      const codeVerifier = arctic.generateCodeVerifier();
      const scopes = ["openid", "profile", "email"];
      const url = google.createAuthorizationURL(state, codeVerifier, scopes);

      res.cookie("google_oauth_state", state, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 60 * 10 * 1000, // 10 minutes
        sameSite: "lax",
        path: "/",
      });
      res.cookie("google_code_verifier", codeVerifier, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 60 * 10 * 1000,
        sameSite: "lax",
        path: "/",
      });

      res.redirect(url.toString());
    } catch (err) {
      googleLog.error({ err }, "init error");
      res.redirect(frontendRedirect("/?auth_error=1"));
    }
  });

  router.get("/google/callback", async (req, res) => {
    if (!google) { res.redirect(frontendRedirect("/?auth_error=not_configured")); return; }
    try {
      const code = req.query.code as string | undefined;
      const state = req.query.state as string | undefined;
      const storedState = (req as any).cookies?.google_oauth_state
        ?? parseCookie(req.headers.cookie ?? "", "google_oauth_state");
      const codeVerifier = (req as any).cookies?.google_code_verifier
        ?? parseCookie(req.headers.cookie ?? "", "google_code_verifier");

      if (!code || !state || !storedState || state !== storedState || !codeVerifier) {
        googleLog.error({
          hasCode: !!code, hasState: !!state, hasStoredState: !!storedState,
          match: state === storedState, hasVerifier: !!codeVerifier,
        }, "state mismatch");
        return res.redirect(frontendRedirect("/?auth_error=1"));
      }

      const tokens = await google.validateAuthorizationCode(code, codeVerifier);
      const accessToken = tokens.accessToken();

      const userResponse = await fetch(
        "https://openidconnect.googleapis.com/v1/userinfo",
        { headers: { Authorization: `Bearer ${accessToken}` } }
      );
      if (!userResponse.ok) {
        googleLog.error({ status: userResponse.status }, "userinfo fetch failed");
        return res.redirect(frontendRedirect("/?auth_error=1"));
      }

      const googleUser = (await userResponse.json()) as {
        sub: string;
        email: string;
        email_verified?: boolean;
        name?: string;
        picture?: string;
      };

      if (!googleUser.email || googleUser.email_verified !== true) {
        googleLog.error(
          { sub: googleUser.sub, hasEmail: !!googleUser.email, verified: googleUser.email_verified },
          "email not verified"
        );
        return res.redirect(frontendRedirect("/?auth_error=email_unverified"));
      }

      const user = upsertUser(db, {
        provider: "google",
        providerId: googleUser.sub,
        email: googleUser.email,
        name: googleUser.name ?? null,
        avatarUrl: googleUser.picture ?? null,
      });

      const session = await lucia.createSession(user.id, {});
      res.appendHeader(
        "Set-Cookie",
        lucia.createSessionCookie(session.id).serialize()
      );

      // Clear OAuth cookies
      res.cookie("google_oauth_state", "", { maxAge: 0, path: "/" });
      res.cookie("google_code_verifier", "", { maxAge: 0, path: "/" });

      res.redirect(frontendRedirect("/"));
    } catch (err) {
      googleLog.error({ err }, "callback error");
      res.redirect(frontendRedirect("/?auth_error=1"));
    }
  });


  // ── GitHub OAuth ──

  router.get("/github", async (_req, res) => {
    if (!github) { res.redirect(frontendRedirect("/?auth_error=not_configured")); return; }
    try {
      const state = arctic.generateState();
      const scopes = ["user:email"];
      const url = github.createAuthorizationURL(state, scopes);

      res.cookie("github_oauth_state", state, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 60 * 10 * 1000,
        sameSite: "lax",
        path: "/",
      });

      res.redirect(url.toString());
    } catch (err) {
      githubLog.error({ err }, "init error");
      res.redirect(frontendRedirect("/?auth_error=1"));
    }
  });

  router.get("/github/callback", async (req, res) => {
    if (!github) { res.redirect(frontendRedirect("/?auth_error=not_configured")); return; }
    try {
      const code = req.query.code as string | undefined;
      const state = req.query.state as string | undefined;
      const storedState = (req as any).cookies?.github_oauth_state
        ?? parseCookie(req.headers.cookie ?? "", "github_oauth_state");

      if (!code || !state || !storedState || state !== storedState) {
        githubLog.error({
          hasCode: !!code, hasState: !!state, hasStoredState: !!storedState,
          match: state === storedState,
        }, "state mismatch");
        return res.redirect(frontendRedirect("/?auth_error=1"));
      }

      const tokens = await github.validateAuthorizationCode(code);
      const accessToken = tokens.accessToken();

      // Get user profile
      const userResponse = await fetch("https://api.github.com/user", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!userResponse.ok) {
        githubLog.error({ status: userResponse.status, body: await userResponse.text() }, "user fetch failed");
        return res.redirect(frontendRedirect("/?auth_error=1"));
      }

      const githubUser = (await userResponse.json()) as {
        id: number;
        login: string;
        name?: string;
        avatar_url?: string;
      };

      // Always resolve email from the verified emails list — the profile email
      // is not guaranteed to be verified, and email is used to link accounts.
      const emailsResponse = await fetch("https://api.github.com/user/emails", {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!emailsResponse.ok) {
        githubLog.error({ status: emailsResponse.status, login: githubUser.login }, "emails fetch failed");
        return res.redirect(frontendRedirect("/?auth_error=1"));
      }
      const emails = (await emailsResponse.json()) as Array<{
        email: string;
        primary: boolean;
        verified: boolean;
      }>;
      // Prefer the primary verified email, then any verified email.
      const email =
        emails.find((e) => e.primary && e.verified)?.email ??
        emails.find((e) => e.verified)?.email ??
        null;

      if (!email) {
        githubLog.error({ login: githubUser.login }, "no verified email found for user");
        return res.redirect(frontendRedirect("/?auth_error=email_unverified"));
      }

      const user = upsertUser(db, {
        provider: "github",
        providerId: String(githubUser.id),
        email,
        name: githubUser.name ?? githubUser.login,
        avatarUrl: githubUser.avatar_url ?? null,
      });

      const session = await lucia.createSession(user.id, {});
      res.appendHeader(
        "Set-Cookie",
        lucia.createSessionCookie(session.id).serialize()
      );

      // Clear OAuth cookie
      res.cookie("github_oauth_state", "", { maxAge: 0, path: "/" });

      res.redirect(frontendRedirect("/"));
    } catch (err) {
      githubLog.error({ err }, "callback error");
      res.redirect(frontendRedirect("/?auth_error=1"));
    }
  });

  // ── Logout ──

  router.post("/logout", requireAuth, async (req, res) => {
    try {
      await lucia.invalidateSession(req.session!.id);
      res.appendHeader(
        "Set-Cookie",
        lucia.createBlankSessionCookie().serialize()
      );
      res.status(200).json({ success: true });
    } catch {
      res.status(500).json({ error: "internal" });
    }
  });

  // ── Current user ──

  router.get("/me", (req, res) => {
    if (!req.user) {
      res.json(null);
      return;
    }
    res.json({
      id: req.user.id,
      email: req.user.email,
      name: req.user.name,
      avatarUrl: req.user.avatarUrl,
      plan: req.user.plan,
      role: (req.user as any).role,
    });
  });

  return router;
}

// ── Helpers ──

interface OAuthProfile {
  provider: "google" | "github";
  providerId: string;
  email: string;
  name: string | null;
  avatarUrl: string | null;
}

/**
 * Upsert user: find by provider+provider_id, then by email, or create new.
 * If the same email exists from a different provider, link to that account
 * (update provider/provider_id so future logins match directly).
 */
export function upsertUser(
  db: Database.Database,
  profile: OAuthProfile
): { id: string } {
  const adminEmails = (process.env.ADMIN_EMAILS || "")
    .split(",")
    .map((e) => e.trim().toLowerCase())
    .filter(Boolean);

  // 1. Exact match on provider + provider_id (returning user, same provider)
  const byProvider = db
    .prepare("SELECT id FROM users WHERE provider = ? AND provider_id = ?")
    .get(profile.provider, profile.providerId) as { id: string } | undefined;

  if (byProvider) {
    db.prepare(
      "UPDATE users SET name = ?, avatar_url = ?, email = ?, last_login_at = datetime('now') WHERE id = ?"
    ).run(profile.name, profile.avatarUrl, profile.email, byProvider.id);
    return { id: byProvider.id };
  }

  // 2. Same email from a different provider — link accounts
  const byEmail = db
    .prepare("SELECT id FROM users WHERE email = ?")
    .get(profile.email) as { id: string } | undefined;

  if (byEmail) {
    db.prepare(
      "UPDATE users SET name = ?, avatar_url = ?, provider = ?, provider_id = ?, last_login_at = datetime('now') WHERE id = ?"
    ).run(profile.name, profile.avatarUrl, profile.provider, profile.providerId, byEmail.id);
    return { id: byEmail.id };
  }

  // 3. Brand new user
  const id = crypto.randomUUID();
  const role = adminEmails.includes(profile.email.toLowerCase()) ? "admin" : "user";
  db.prepare(
    `INSERT INTO users (id, email, name, avatar_url, provider, provider_id, plan, role, last_login_at)
     VALUES (?, ?, ?, ?, ?, ?, 'free', ?, datetime('now'))`
  ).run(id, profile.email, profile.name, profile.avatarUrl, profile.provider, profile.providerId, role);

  return { id };
}

/**
 * Simple cookie parser — extracts a single cookie value by name.
 */
function parseCookie(cookieHeader: string, name: string): string | null {
  const match = cookieHeader
    .split(";")
    .map((c) => c.trim())
    .find((c) => c.startsWith(`${name}=`));
  return match ? decodeURIComponent(match.substring(name.length + 1)) : null;
}
