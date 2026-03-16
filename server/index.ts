import express from "express";
import cors from "cors";
import compression from "compression";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { rateLimiter } from "./middleware/rateLimit.js";
import { validateRequest } from "./middleware/validateRequest.js";
import fetchRoute from "./routes/fetch.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const isProduction = process.env.NODE_ENV === "production";

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;

// Gzip/brotli compression for all responses
app.use(compression());

// CORS — only needed in dev (in prod, frontend is served from same origin)
if (!isProduction) {
  app.use(
    cors({
      origin: process.env.CORS_ORIGIN || "http://localhost:5173",
    })
  );
}

// Security headers
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// Rate limiting on API routes
app.use("/api", rateLimiter);

// Fetch endpoint with domain validation
app.use("/api/fetch", validateRequest, fetchRoute);

// In production, serve the built frontend
if (isProduction) {
  const distPath = path.resolve(__dirname, "..", "dist");
  app.use(express.static(distPath, { maxAge: "1y", immutable: true }));
  // index.html should not be cached aggressively
  app.get("*", (_req, res) => {
    res.setHeader("Cache-Control", "no-cache");
    res.sendFile(path.join(distPath, "index.html"));
  });
}

app.listen(PORT, () => {
  console.log(`Server listening on port ${PORT} (${isProduction ? "production" : "development"})`);
});

export default app;
