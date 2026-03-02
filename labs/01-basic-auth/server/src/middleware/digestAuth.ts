import { Request, Response, NextFunction } from "express";
import { createHash, randomBytes } from "crypto";
import { createErrorResponse } from "@auth-labs/shared";

interface DigestUser {
  username: string;
  password: string;
  role: "admin" | "user" | "guest";
}

// In-memory user store
const DIGEST_USERS: DigestUser[] = [
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

const REALM = process.env.DIGEST_AUTH_REALM || "AuthLabs-Digest-Realm";

// Nonce store: nonce → { timestamp, count }
// Production: use Redis with TTL
const nonceStore = new Map<string, { timestamp: number; count: number }>();
const NONCE_TTL_MS = 5 * 60 * 1000; // 5 minutes

function md5(data: string): string {
  return createHash("md5").update(data).digest("hex");
}

function generateNonce(): string {
  const nonce = randomBytes(16).toString("hex");
  nonceStore.set(nonce, { timestamp: Date.now(), count: 0 });
  return nonce;
}

function isNonceValid(nonce: string): boolean {
  const entry = nonceStore.get(nonce);
  if (!entry) return false;
  if (Date.now() - entry.timestamp > NONCE_TTL_MS) {
    nonceStore.delete(nonce);
    return false;
  }
  return true;
}

function generateOpaque(): string {
  return md5(REALM + Date.now().toString());
}

/**
 * Parse Digest Authorization header into key-value map
 * Example: Digest username="admin", realm="...", nonce="...", ...
 */
function parseDigestHeader(header: string): Record<string, string> | null {
  if (!header.startsWith("Digest ")) return null;

  const params: Record<string, string> = {};
  const parts = header.slice("Digest ".length);

  // Match key="value" or key=value patterns
  const regex = /(\w+)=(?:"([^"]*)"|([\w/:.@!#$%^&*()\-+]+))/g;
  let match: RegExpExecArray | null;

  while ((match = regex.exec(parts)) !== null) {
    params[match[1]] = match[2] !== undefined ? match[2] : match[3];
  }

  return params;
}

export function digestAuthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const authHeader = req.headers["authorization"];

  // Step 1: No / non-Digest header → send challenge
  if (!authHeader || !authHeader.startsWith("Digest ")) {
    const nonce = generateNonce();
    const opaque = generateOpaque();

    res.setHeader(
      "WWW-Authenticate",
      `Digest realm="${REALM}", qop="auth", algorithm=MD5, nonce="${nonce}", opaque="${opaque}"`,
    );
    res
      .status(401)
      .json(createErrorResponse("Digest Authentication required."));
    return;
  }

  // Step 2: Parse the Digest header
  const params = parseDigestHeader(authHeader);
  if (!params) {
    res
      .status(400)
      .json(createErrorResponse("Malformed Digest Authorization header."));
    return;
  }

  const { username, realm, nonce, uri, qop, nc, cnonce, response, opaque } =
    params;

  // Step 3: Validate required fields
  if (!username || !realm || !nonce || !uri || !response) {
    res
      .status(400)
      .json(createErrorResponse("Missing required Digest Auth parameters."));
    return;
  }

  // Step 4: Validate nonce (replay protection)
  if (!isNonceValid(nonce)) {
    const newNonce = generateNonce();
    res.setHeader(
      "WWW-Authenticate",
      `Digest realm="${REALM}", qop="auth", algorithm=MD5, nonce="${newNonce}", opaque="${opaque}", stale=true`,
    );
    res
      .status(401)
      .json(createErrorResponse("Nonce expired. Please retry with new nonce."));
    return;
  }

  // Step 5: Find user
  const user = DIGEST_USERS.find((u) => u.username === username);
  if (!user) {
    res.status(401).json(createErrorResponse("Invalid username."));
    return;
  }

  // Step 6: Compute expected response
  // HA1 = MD5(username:realm:password)
  const HA1 = md5(`${username}:${realm}:${user.password}`);
  // HA2 = MD5(method:digestURI)
  const HA2 = md5(`${req.method}:${uri}`);

  let expectedResponse: string;

  if (qop === "auth") {
    // response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
    expectedResponse = md5(`${HA1}:${nonce}:${nc}:${cnonce}:${qop}:${HA2}`);
  } else {
    // Legacy: response = MD5(HA1:nonce:HA2)
    expectedResponse = md5(`${HA1}:${nonce}:${HA2}`);
  }

  // Step 7: Compare (timing-safe in production: use crypto.timingSafeEqual)
  if (response !== expectedResponse) {
    res.status(401).json(createErrorResponse("Invalid credentials."));
    return;
  }

  // Step 8: Increment nonce usage count (anti-replay)
  const nonceEntry = nonceStore.get(nonce)!;
  nonceStore.set(nonce, { ...nonceEntry, count: nonceEntry.count + 1 });

  // Step 9: Success
  req.authUser = { username: user.username, role: user.role };
  req.authMethod = "digest";
  next();
}
