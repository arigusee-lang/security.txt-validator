import { Router, type Request, type Response } from "express";
import { buildReportHtml, type ReportData } from "../lib/reportRenderer.js";
import { htmlToPdf } from "../lib/pdfRenderer.js";
import { createLogger } from "../lib/logger.js";

const log = createLogger("export/pdf");

const FILENAME_RE = /[^a-zA-Z0-9._-]/g;

function safeFilename(domain: string): string {
  const cleaned = String(domain || "domain").replace(FILENAME_RE, "-").slice(0, 100);
  return cleaned || "domain";
}

// Sanity check: scanIds are UUIDs (crypto.randomUUID). Reject anything else so
// we never echo arbitrary user-supplied content into the footer URL.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function originFromRequest(req: Request): string {
  const proto = (req.headers["x-forwarded-proto"] as string)?.split(",")[0]?.trim() || req.protocol;
  const host = (req.headers["x-forwarded-host"] as string) || req.headers.host || "";
  return `${proto}://${host}`;
}

function parsePayload(req: Request): ReportData | null {
  const body = req.body;
  if (!body || typeof body !== "object") return null;
  if (typeof body.domain !== "string" || !body.domain) return null;

  const scanId = typeof body.scanId === "string" && UUID_RE.test(body.scanId) ? body.scanId : null;

  // Whitelist top-level fields. Per-section shapes are trusted because the
  // renderer escapes every value it interpolates and never executes input.
  return {
    domain: body.domain,
    scanDate: typeof body.scanDate === "string" ? body.scanDate : new Date().toISOString(),
    score: body.score ?? null,
    scanId,
    verifyBaseUrl: scanId ? originFromRequest(req) : null,
    diff: body.diff ?? null,
    dns: body.dns ?? null,
    web: body.web ?? null,
    expiry: body.expiry ?? null,
    ct: body.ct ?? null,
    redirects: body.redirects ?? null,
    reputation: body.reputation ?? null,
  };
}

export function createExportRoutes(): Router {
  const router = Router();

  router.post("/html", (req: Request, res: Response) => {
    const data = parsePayload(req);
    if (!data) {
      res.status(400).json({ error: "invalid_request", message: "Missing or invalid scan data" });
      return;
    }

    const html = buildReportHtml(data);
    const filename = `${safeFilename(data.domain)}-security-report.html`;

    res.setHeader("Content-Type", "text/html; charset=utf-8");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(html);
  });

  // PDF export is disabled on memory-constrained deployments (e.g. GCE e2-micro):
  // Puppeteer/Chromium would be resident in RAM. Set PDF_EXPORT_ENABLED=true to
  // re-enable on a host with enough memory. The frontend greys out the menu item.
  const pdfEnabled = process.env.PDF_EXPORT_ENABLED === "true";

  router.post("/pdf", async (req: Request, res: Response) => {
    if (!pdfEnabled) {
      res.status(503).json({
        error: "pdf_disabled",
        message: "PDF export is disabled on this deployment. Use HTML or CSV export instead.",
      });
      return;
    }

    const data = parsePayload(req);
    if (!data) {
      res.status(400).json({ error: "invalid_request", message: "Missing or invalid scan data" });
      return;
    }

    try {
      const html = buildReportHtml(data);
      const pdf = await htmlToPdf(html);
      const filename = `${safeFilename(data.domain)}-security-report.pdf`;

      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
      res.send(pdf);
    } catch (err) {
      log.error({ err: (err as Error).message }, "render failed");
      res.status(500).json({
        error: "render_failed",
        message: "Could not generate PDF. The server may be missing Chromium dependencies.",
      });
    }
  });

  return router;
}
