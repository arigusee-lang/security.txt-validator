import { Router } from "express";
import { safeFetch } from "../lib/safeFetch.js";
import type { ProxyFetchError } from "../types.js";

const router = Router();

/** Map proxy error codes to HTTP status codes */
const errorStatusMap: Record<string, number> = {
  timeout: 504,
  size_limit: 502,
  dns_failure: 502,
  http_error: 502,
  ssrf_blocked: 403,
  invalid_content_type: 502,
  not_found: 404,
  too_many_redirects: 502,
  invalid_request: 400,
  internal: 500,
};

router.get("/", async (req, res) => {
  const domain = req.query.domain as string;

  try {
    const result = await safeFetch(domain);

    if (!result.success) {
      const errorResult = result as ProxyFetchError;
      const status = errorStatusMap[errorResult.error] || errorResult.httpStatus || 500;
      res.status(status).json(result);
      return;
    }

    res.json(result);
  } catch (err: any) {
    console.error("Unexpected error in fetch handler:", err);
    // If the thrown object has an error field, use it
    if (err && typeof err === "object" && err.error) {
      const status = errorStatusMap[err.error] || err.httpStatus || 500;
      res.status(status).json({
        success: false,
        error: err.error,
        message: err.message || "An error occurred.",
        ...(err.httpStatus ? { httpStatus: err.httpStatus } : {}),
      });
      return;
    }
    res.status(500).json({
      success: false,
      error: "internal",
      message: "Internal server error.",
    });
  }
});

export default router;
