// ─── User Types ───────────────────────────────────────────────────────────────

export interface User {
  id: string;
  username: string;
  email: string;
  role: "admin" | "user" | "guest";
  createdAt: string;
}

export interface UserCredentials {
  username: string;
  password: string;
}

// ─── API Response Types ────────────────────────────────────────────────────────

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  timestamp: string;
}

export interface AuthResponse {
  user: Omit<User, "password">;
  method: AuthMethod;
  message: string;
}

// ─── Auth Method Types ─────────────────────────────────────────────────────────

export type AuthMethod =
  | "basic"
  | "digest"
  | "session"
  | "api-key"
  | "jwt"
  | "refresh-token"
  | "sso"
  | "oauth2"
  | "oidc";

// ─── Basic Auth Types ──────────────────────────────────────────────────────────

export interface BasicAuthRequest {
  username: string;
  password: string;
}

export interface DigestAuthChallenge {
  realm: string;
  nonce: string;
  qop: string;
  algorithm: string;
  opaque: string;
}

export interface DigestAuthResponse {
  username: string;
  realm: string;
  nonce: string;
  uri: string;
  qop: string;
  nc: string;
  cnonce: string;
  response: string;
  opaque: string;
}

// ─── Helper Functions ──────────────────────────────────────────────────────────

export function createSuccessResponse<T>(
  data: T,
  message?: string,
): ApiResponse<T> {
  return {
    success: true,
    data,
    message,
    timestamp: new Date().toISOString(),
  };
}

export function createErrorResponse(error: string): ApiResponse<never> {
  return {
    success: false,
    error,
    timestamp: new Date().toISOString(),
  };
}
