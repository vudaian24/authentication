import { Router, Request, Response } from "express";
import { createSuccessResponse, AuthResponse } from "@auth-labs/shared";
import { basicAuthMiddleware } from "../middleware/basicAuth";
import { digestAuthMiddleware } from "../middleware/digestAuth";
import { v4 as uuidv4 } from "uuid";

const router = Router();

// ─── Health Check ──────────────────────────────────────────────────────────────

router.get("/health", (_req: Request, res: Response) => {
  res.json(
    createSuccessResponse(
      { status: "ok", lab: "01-basic-auth", port: process.env.PORT || 3001 },
      "Server is running",
    ),
  );
});

// ─── Basic Auth Routes ─────────────────────────────────────────────────────────

/**
 * GET /api/basic/protected
 * Protected resource using Basic Auth
 */
router.get(
  "/basic/protected",
  basicAuthMiddleware,
  (req: Request, res: Response) => {
    const authResponse: AuthResponse = {
      user: {
        id: uuidv4(),
        username: req.authUser!.username,
        email: `${req.authUser!.username}@authlabs.dev`,
        role: req.authUser!.role,
        createdAt: new Date().toISOString(),
      },
      method: "basic",
      message: `Welcome, ${req.authUser!.username}! You authenticated via Basic Auth.`,
    };

    res.json(createSuccessResponse(authResponse, "Basic Auth successful"));
  },
);

/**
 * GET /api/basic/profile
 * Another protected resource to demonstrate multiple endpoints
 */
router.get(
  "/basic/profile",
  basicAuthMiddleware,
  (req: Request, res: Response) => {
    res.json(
      createSuccessResponse(
        {
          username: req.authUser!.username,
          role: req.authUser!.role,
          accessLevel:
            req.authUser!.role === "admin" ? "Full Access" : "Read Only",
          lastLogin: new Date().toISOString(),
          method: "Basic Auth (RFC 7617)",
          securityNote:
            "Credentials are Base64 encoded, NOT encrypted. Always use HTTPS!",
        },
        "Profile fetched successfully",
      ),
    );
  },
);

// ─── Digest Auth Routes ────────────────────────────────────────────────────────

/**
 * GET /api/digest/protected
 * Protected resource using Digest Auth
 */
router.get(
  "/digest/protected",
  digestAuthMiddleware,
  (req: Request, res: Response) => {
    const authResponse: AuthResponse = {
      user: {
        id: uuidv4(),
        username: req.authUser!.username,
        email: `${req.authUser!.username}@authlabs.dev`,
        role: req.authUser!.role,
        createdAt: new Date().toISOString(),
      },
      method: "digest",
      message: `Welcome, ${req.authUser!.username}! You authenticated via Digest Auth.`,
    };

    res.json(createSuccessResponse(authResponse, "Digest Auth successful"));
  },
);

/**
 * GET /api/digest/profile
 */
router.get(
  "/digest/profile",
  digestAuthMiddleware,
  (req: Request, res: Response) => {
    res.json(
      createSuccessResponse(
        {
          username: req.authUser!.username,
          role: req.authUser!.role,
          accessLevel:
            req.authUser!.role === "admin" ? "Full Access" : "Read Only",
          lastLogin: new Date().toISOString(),
          method: "Digest Auth (RFC 7616)",
          securityNote:
            "Password is never sent over the wire. Uses MD5 challenge-response with nonce.",
        },
        "Profile fetched successfully",
      ),
    );
  },
);

// ─── Info route — show how to authenticate ────────────────────────────────────

router.get("/info", (_req: Request, res: Response) => {
  res.json(
    createSuccessResponse({
      lab: "01 - Basic Auth & Digest Auth",
      endpoints: {
        basicAuth: {
          protected: "GET /api/basic/protected",
          profile: "GET /api/basic/profile",
          howTo:
            "Set Authorization header: Basic base64(username:password). Credentials: admin:secret123 or user:password456",
        },
        digestAuth: {
          protected: "GET /api/digest/protected",
          profile: "GET /api/digest/profile",
          howTo:
            "First request returns 401 with nonce. Client computes MD5 hash and retries with Digest credentials.",
        },
      },
      testCredentials: [
        { username: "admin", password: "secret123", role: "admin" },
        { username: "user", password: "password456", role: "user" },
      ],
    }),
  );
});

export default router;
