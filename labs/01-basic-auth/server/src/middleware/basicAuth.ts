import { Request, Response, NextFunction } from "express";
import { createErrorResponse } from "@auth-labs/shared";

interface BasicAuthUser {
  username: string;
  password: string;
  role: "admin" | "user" | "guest";
}

// In-memory user store (production: use DB with bcrypt hashed passwords)
const USERS: BasicAuthUser[] = [
  {
    username: process.env.BASIC_AUTH_USERNAME || "admin",
    password: process.env.BASIC_AUTH_PASSWORD || "secret123",
    role: "admin",
  },
  {
    username: process.env.BASIC_AUTH_USERNAME_2 || "user",
    password: process.env.BASIC_AUTH_PASSWORD_2 || "password456",
    role: "user",
  },
];

// Attach authenticated user to request
declare global {
  namespace Express {
    interface Request {
      authUser?: Omit<BasicAuthUser, "password">;
      authMethod?: string;
    }
  }
}

export function basicAuthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const authHeader = req.headers["authorization"];

  // Step 1: No Authorization header → challenge client
  if (!authHeader || !authHeader.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="AuthLabs"');
    res
      .status(401)
      .json(
        createErrorResponse(
          "Authentication required. Please provide Basic Auth credentials.",
        ),
      );
    return;
  }

  // Step 2: Decode Base64 credentials
  const base64Credentials = authHeader.slice("Basic ".length);
  let decoded: string;

  try {
    decoded = Buffer.from(base64Credentials, "base64").toString("utf-8");
  } catch {
    res
      .status(400)
      .json(
        createErrorResponse("Invalid Base64 encoding in Authorization header."),
      );
    return;
  }

  // Step 3: Split into username:password (password may contain ':')
  const colonIndex = decoded.indexOf(":");
  if (colonIndex === -1) {
    res
      .status(400)
      .json(
        createErrorResponse(
          'Invalid credentials format. Expected "username:password".',
        ),
      );
    return;
  }

  const username = decoded.slice(0, colonIndex);
  const password = decoded.slice(colonIndex + 1);

  // Step 4: Find user (constant-time comparison recommended in production)
  const user = USERS.find(
    (u) => u.username === username && u.password === password,
  );

  if (!user) {
    res.setHeader("WWW-Authenticate", 'Basic realm="AuthLabs"');
    res.status(401).json(createErrorResponse("Invalid username or password."));
    return;
  }

  // Step 5: Attach user info to request
  req.authUser = { username: user.username, role: user.role };
  req.authMethod = "basic";
  next();
}
