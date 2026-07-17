import { config as loadEnv } from "dotenv";
import path from "node:path";
import dns from "node:dns";

// Load env BEFORE any other module is evaluated.
//
// ES module imports are evaluated before the importing module's body runs, so
// loading dotenv in index.ts's body was too late — modules like ctLogsChecker
// read process.env at evaluation time (during the import phase) and saw empty
// values. Importing this module first, before any env-reading module, fixes the
// ordering: this body runs as soon as the import is resolved.
const envFile = process.env.NODE_ENV === "production" ? ".env.production" : ".env.local";
loadEnv({ path: path.resolve(process.cwd(), envFile) });
// Fallback: also try .env
loadEnv();

// DNS resolver fallback for local dev. Some Node builds on Windows (notably via
// nvm-for-windows) fail to read the OS DNS configuration and have c-ares fall
// back to 127.0.0.1, where nothing listens on :53 — every dns.resolve* then
// fails with ECONNREFUSED. Only override when the system resolver is loopback,
// so prod (GCE internal resolver 169.254.169.254) is never touched.
const sysServers = dns.getServers();
if (sysServers.every((s) => s.startsWith("127.") || s === "::1")) {
  dns.setServers(["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"]);
}
