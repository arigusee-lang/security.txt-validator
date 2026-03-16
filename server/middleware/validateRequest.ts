import type { Request, Response, NextFunction } from "express";

/**
 * Validates and sanitizes the `domain` query parameter.
 * Rejects missing, empty, or malformed domain values.
 */
export function validateRequest(req: Request, res: Response, next: NextFunction): void {
  const domain = req.query.domain;

  if (!domain || typeof domain !== "string") {
    res.status(400).json({
      success: false,
      error: "invalid_request",
      message: "A valid domain is required.",
    });
    return;
  }

  const trimmed = domain.trim();

  if (trimmed.length === 0) {
    res.status(400).json({
      success: false,
      error: "invalid_request",
      message: "A valid domain is required.",
    });
    return;
  }

  // Allow domain names and IPs only — no schemes, paths, spaces, or control chars
  // Valid: example.com, sub.example.com, 1.2.3.4
  const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$/;
  if (!domainPattern.test(trimmed) || trimmed.length > 253) {
    res.status(400).json({
      success: false,
      error: "invalid_request",
      message: "A valid domain is required.",
    });
    return;
  }

  // Attach sanitized domain to query for downstream use
  req.query.domain = trimmed;
  next();
}
