import "dotenv/config";
import express, { Request, Response, NextFunction } from "express";
import cors from "cors";
import authRoutes from "./routes/auth";
import { createErrorResponse } from "@auth-labs/shared";

const app = express();
const PORT = parseInt(process.env.PORT || "3001", 10);
const CLIENT_URL = process.env.CLIENT_URL || "http://localhost:5173";

// ─── Middleware ────────────────────────────────────────────────────────────────

app.use(
  cors({
    origin: CLIENT_URL,
    credentials: true,
    // Expose WWW-Authenticate header so client can read it
    exposedHeaders: ["WWW-Authenticate"],
    allowedHeaders: ["Authorization", "Content-Type"],
  }),
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logger (dev only)
if (process.env.NODE_ENV === "development") {
  app.use((req: Request, _res: Response, next: NextFunction) => {
    const authHeader = req.headers["authorization"];
    const authType = authHeader?.split(" ")[0] || "None";
    console.log(
      `[${new Date().toISOString()}] ${req.method} ${req.path} | Auth: ${authType}`,
    );
    next();
  });
}

// ─── Routes ───────────────────────────────────────────────────────────────────

app.use("/api", authRoutes);

// 404 handler
app.use((_req: Request, res: Response) => {
  res.status(404).json(createErrorResponse("Route not found"));
});

// Global error handler — never expose stack traces
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error("[ERROR]", err.message);
  res.status(500).json(createErrorResponse("Internal server error"));
});

// ─── Start ────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log("");
  console.log("╔══════════════════════════════════════════╗");
  console.log("║   🔐 Lab 01 — Basic & Digest Auth        ║");
  console.log("╠══════════════════════════════════════════╣");
  console.log(`║   Server  → http://localhost:${PORT}         ║`);
  console.log(`║   Client  → ${CLIENT_URL}       ║`);
  console.log("╠══════════════════════════════════════════╣");
  console.log("║   Endpoints:                             ║");
  console.log("║   GET /api/info                          ║");
  console.log("║   GET /api/basic/protected               ║");
  console.log("║   GET /api/basic/profile                 ║");
  console.log("║   GET /api/digest/protected              ║");
  console.log("║   GET /api/digest/profile                ║");
  console.log("╠══════════════════════════════════════════╣");
  console.log("║   Credentials:                           ║");
  console.log("║   admin / secret123    (role: admin)     ║");
  console.log("║   user  / password456  (role: user)      ║");
  console.log("╚══════════════════════════════════════════╝");
  console.log("");
});

export default app;
