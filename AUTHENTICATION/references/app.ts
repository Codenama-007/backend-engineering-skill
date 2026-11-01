/**
 * Authentication templates: Beginner -> Intermediate -> Advanced -> Critical (TypeScript)
 *
 * Install: npm i argon2 jose otplib && npm i -D typescript @types/node @types/express
 * Runtime: Node 20+, tsconfig with "module": "NodeNext", "target": "ES2022", "strict": true
 *
 * IMPORTANT
 * - Framework-agnostic building blocks. Maps stand in for your database/Redis.
 *   Replace them before real use.
 * - Each section is labeled with the level it belongs to. Higher levels build
 *   on the lower ones: use only the sections your project actually needs.
 * - The CRITICAL section is a starting skeleton, NOT a compliant implementation.
 *   It requires human security review, pen testing, and compliance sign-off.
 */

import crypto from "node:crypto";
import argon2 from "argon2";
import {
  SignJWT, jwtVerify, importPKCS8, importSPKI, createRemoteJWKSet, type JWTPayload,
} from "jose";
import { authenticator } from "otplib";
import type { NextFunction, Request, Response } from "express";

// ============================================================================
// AUTHENTICATION LEVEL: BEGINNER
// Use for: prototypes, MVPs, internal tools.
// Covers: password hashing, server-side sessions, generic errors, rate limiting.
// ============================================================================

type Role = "user" | "admin";

interface User {
  id: string;
  email: string;
  passwordHash: string;
  role: Role;
  verified: boolean;
}

interface Session {
  userId: string;
  expiresAt: number;
}

const users = new Map<string, User>();          // email -> user (replace with DB)
const sessions = new Map<string, Session>();    // sessionId -> session
const attempts = new Map<string, number[]>();   // key -> timestamps (replace with Redis)

const SESSION_TTL_MS = 7 * 24 * 60 * 60 * 1000;

// Use these flags when setting the cookie (e.g., res.cookie("sid", id, SESSION_COOKIE_OPTIONS))
export const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,        // HTTPS only
  sameSite: "lax" as const,
  maxAge: SESSION_TTL_MS,
};

const randomToken = (bytes = 32): string => crypto.randomBytes(bytes).toString("base64url");
const sha256 = (value: string): string => crypto.createHash("sha256").update(value).digest("hex");
const normalizeEmail = (email: string): string => email.trim().toLowerCase();

// Hash verified when the email does not exist, so response timing stays equal
const DUMMY_HASH = await argon2.hash("dummy-password-for-timing", { type: argon2.argon2id });

function rateLimited(key: string, limit = 5, windowMs = 60_000): boolean {
  const now = Date.now();
  const recent = (attempts.get(key) ?? []).filter((t) => now - t < windowMs);
  recent.push(now);
  attempts.set(key, recent);
  return recent.length > limit;
}

export async function register(email: string, password: string): Promise<User> {
  email = normalizeEmail(email);
  if (password.length < 12) throw new Error("Password must be at least 12 characters");
  if (users.has(email)) throw new Error("Unable to register with those details"); // no enumeration
  const user: User = {
    id: crypto.randomUUID(),
    email,
    passwordHash: await argon2.hash(password, { type: argon2.argon2id }),
    role: "user",
    verified: false,
  };
  users.set(email, user);
  return user;
}

/** Returns a NEW session id. Set it in the cookie using SESSION_COOKIE_OPTIONS. */
export async function login(email: string, password: string, ip: string): Promise<string> {
  email = normalizeEmail(email);
  if (rateLimited(`login:${ip}`) || rateLimited(`login:${email}`)) {
    throw new Error("Too many attempts. Try again later.");
  }
  const user = users.get(email);
  const ok = await argon2.verify(user ? user.passwordHash : DUMMY_HASH, password);
  if (!user || !ok) throw new Error("Invalid email or password"); // generic on purpose

  // Always issue a fresh session id on login (prevents session fixation)
  const sessionId = randomToken();
  sessions.set(sessionId, { userId: user.id, expiresAt: Date.now() + SESSION_TTL_MS });
  return sessionId;
}

export function getSessionUser(sessionId?: string): User | null {
  const s = sessionId ? sessions.get(sessionId) : undefined;
  if (!s || s.expiresAt < Date.now()) {
    if (sessionId) sessions.delete(sessionId);
    return null;
  }
  return [...users.values()].find((u) => u.id === s.userId) ?? null;
}

export function logout(sessionId: string): void {
  sessions.delete(sessionId); // destroy server-side, then clear the cookie
}

// Express-style middleware (needs cookie-parser)
export const requireLogin = (req: Request, res: Response, next: NextFunction): void => {
  const user = getSessionUser(req.cookies?.sid);
  if (!user) {
    res.status(401).json({ error: "Login required" });
    return;
  }
  (req as Request & { user?: User }).user = user;
  next();
};

// ============================================================================
// AUTHENTICATION LEVEL: INTERMEDIATE
// Use for: production web/mobile apps and SaaS.
// Covers: JWT access tokens, rotating refresh tokens, one-time tokens
//         (verify email / password reset), RBAC with ownership checks, TOTP 2FA.
// ============================================================================

const ISSUER = "https://auth.example.com";
const AUDIENCE = "example-api";
const ACCESS_TTL = "10m";
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const JWT_ALG = "RS256"; // pin the algorithm explicitly

type SigningKey = Awaited<ReturnType<typeof importPKCS8>>;

// PEM keys from your secret manager
const privateKey: SigningKey | null = process.env.JWT_PRIVATE_KEY
  ? await importPKCS8(process.env.JWT_PRIVATE_KEY, JWT_ALG) : null;
const publicKey: SigningKey | null = process.env.JWT_PUBLIC_KEY
  ? await importSPKI(process.env.JWT_PUBLIC_KEY, JWT_ALG) : null;
const KEY_ID = process.env.JWT_KEY_ID ?? "key-1";

interface RefreshRecord { userId: string; familyId: string; expiresAt: number; revoked: boolean }
interface OneTimeRecord { userId: string; purpose: OneTimePurpose; expiresAt: number; used: boolean }
type OneTimePurpose = "verify_email" | "reset_password";

const refreshTokens = new Map<string, RefreshRecord>();   // sha256(token) -> record
const oneTimeTokens = new Map<string, OneTimeRecord>();   // sha256(token) -> record

export async function issueAccessToken(user: User, extraClaims: JWTPayload = {}): Promise<string> {
  if (!privateKey) throw new Error("JWT private key not configured");
  return new SignJWT({ role: user.role, ...extraClaims })
    .setProtectedHeader({ alg: JWT_ALG, kid: KEY_ID })
    .setSubject(user.id)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime(ACCESS_TTL)
    .setJti(crypto.randomUUID())
    .sign(privateKey);
}

export async function verifyAccessToken(token: string): Promise<JWTPayload & { role: Role }> {
  if (!publicKey) throw new Error("JWT public key not configured");
  const { payload } = await jwtVerify(token, publicKey, {
    algorithms: [JWT_ALG], // never trust the token's own "alg" header
    issuer: ISSUER,
    audience: AUDIENCE,
    requiredClaims: ["exp", "iat", "sub", "jti"],
  });
  return payload as JWTPayload & { role: Role };
}

export function issueRefreshToken(userId: string, familyId: string = crypto.randomUUID()): string {
  const raw = randomToken(48); // opaque, NOT a JWT
  refreshTokens.set(sha256(raw), {
    userId, familyId, expiresAt: Date.now() + REFRESH_TTL_MS, revoked: false, // store only the hash
  });
  return raw;
}

/** Detects token theft via reuse and revokes the whole family. */
export async function rotateRefreshToken(
  raw: string,
): Promise<{ accessToken: string; refreshToken: string }> {
  const record = refreshTokens.get(sha256(raw));
  if (!record || record.expiresAt < Date.now()) throw new Error("Invalid refresh token");
  if (record.revoked) {
    for (const r of refreshTokens.values()) if (r.familyId === record.familyId) r.revoked = true;
    throw new Error("Refresh token reuse detected");
  }
  record.revoked = true;
  const user = [...users.values()].find((u) => u.id === record.userId);
  if (!user) throw new Error("Invalid refresh token");
  return {
    accessToken: await issueAccessToken(user),
    refreshToken: issueRefreshToken(user.id, record.familyId),
  };
}

/** Email the raw token as a link; only its hash is stored. */
export function createOneTimeToken(
  userId: string, purpose: OneTimePurpose, ttlMs = 30 * 60 * 1000,
): string {
  const raw = randomToken();
  oneTimeTokens.set(sha256(raw), { userId, purpose, expiresAt: Date.now() + ttlMs, used: false });
  return raw;
}

export function consumeOneTimeToken(raw: string, purpose: OneTimePurpose): string {
  const r = oneTimeTokens.get(sha256(raw));
  if (!r || r.used || r.purpose !== purpose || r.expiresAt < Date.now()) {
    throw new Error("Invalid or expired token");
  }
  r.used = true; // single use
  return r.userId;
}

/** Call after password reset/change so old sessions and tokens stop working. */
export function revokeAllUserTokens(userId: string): void {
  for (const r of refreshTokens.values()) if (r.userId === userId) r.revoked = true;
  for (const [sid, s] of sessions) if (s.userId === userId) sessions.delete(sid);
}

type Permission = "post:read" | "post:create" | "post:delete" | "user:manage";

const ROLE_PERMISSIONS: Record<Role, ReadonlySet<Permission>> = {
  user: new Set<Permission>(["post:read", "post:create"]),
  admin: new Set<Permission>(["post:read", "post:create", "post:delete", "user:manage"]),
};

/** Default deny. Checks role permission AND object ownership (prevents IDOR). */
export function authorize(
  claims: JWTPayload & { role: Role }, permission: Permission, resourceOwnerId?: string,
): boolean {
  if (!ROLE_PERMISSIONS[claims.role]?.has(permission)) return false;
  if (resourceOwnerId && claims.role !== "admin") return claims.sub === resourceOwnerId;
  return true;
}

// Express-style middleware: verifies the bearer token, then checks permission
export const requirePermission =
  (permission: Permission) => async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = req.headers.authorization?.replace(/^Bearer /, "") ?? "";
      const claims = await verifyAccessToken(token);
      if (!authorize(claims, permission)) {
        res.status(403).json({ error: "Forbidden" });
        return;
      }
      (req as Request & { claims?: JWTPayload }).claims = claims;
      next();
    } catch {
      res.status(401).json({ error: "Unauthorized" });
    }
  };

/** TOTP 2FA. Rate-limit this endpoint and store `secret` encrypted at rest. */
export const verifyTotp = (secret: string, code: string): boolean =>
  authenticator.check(code, secret);

/** Show raw codes to the user once; store only the hashes. */
export function generateRecoveryCodes(n = 10): { raw: string[]; hashed: string[] } {
  const raw = Array.from({ length: n }, () => crypto.randomBytes(5).toString("hex"));
  return { raw, hashed: raw.map(sha256) };
}

// ============================================================================
// AUTHENTICATION LEVEL: ADVANCED
// Use for: enterprise SSO, multi-tenant, step-up auth, fine-grained authz.
// Covers: OIDC PKCE + ID token validation, tenant-scoped identity,
//         step-up authentication, attribute-based access control (ABAC).
// Prefer a vetted IdP/library for full flows; these are the core checks.
// ============================================================================

export function generatePkce(): { verifier: string; challenge: string } {
  const verifier = randomToken(64); // keep server-side/session
  const challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
  return { verifier, challenge };
}

interface OidcConfig {
  jwksUri: string;
  issuer: string;
  clientId: string;
  expectedNonce: string;
}

/** Validates signature (via JWKS), issuer, audience, expiry, and nonce. */
export async function verifyOidcIdToken(idToken: string, cfg: OidcConfig): Promise<JWTPayload> {
  const jwks = createRemoteJWKSet(new URL(cfg.jwksUri));
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: cfg.issuer,
    audience: cfg.clientId,
    algorithms: ["RS256", "ES256"],
  });
  const a = Buffer.from(String(payload.nonce ?? ""));
  const b = Buffer.from(cfg.expectedNonce);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new Error("Invalid nonce");
  return payload;
}

/** Identity = (tenant, issuer, sub). Never match accounts on email alone. */
export const identityKey = (tenantId: string, issuer: string, subject: string): string =>
  `${tenantId}|${issuer}|${subject}`;

interface StepUpClaims { auth_time?: number; acr?: string }

/** Demand recent authentication before sensitive actions (change email, payouts). */
export function requireStepUp(
  claims: StepUpClaims, opts: { maxAgeSeconds?: number; requiredAcr?: string } = {},
): void {
  const { maxAgeSeconds = 300, requiredAcr } = opts;
  if (!claims.auth_time || Date.now() / 1000 - claims.auth_time > maxAgeSeconds) {
    throw new Error("step_up_required");
  }
  if (requiredAcr && claims.acr !== requiredAcr) throw new Error("step_up_required");
}

interface PolicySubject { id: string; tenantId: string; department?: string; roles?: string[] }
interface PolicyResource {
  tenantId: string; ownerId?: string; department?: string;
  classification?: "public" | "internal" | "restricted";
}

/** ABAC decision point. Default deny; every rule must be explicit. */
export function evaluatePolicy(
  subject: PolicySubject,
  action: "read" | "write" | "delete",
  resource: PolicyResource,
  context: StepUpClaims = {},
): boolean {
  if (subject.tenantId !== resource.tenantId) return false; // hard tenant isolation
  if (action === "read" && resource.classification === "public") return true;
  if (action === "read" && subject.department === resource.department) return true;
  if (action === "write" && resource.ownerId === subject.id) return true;
  if (action === "delete" && subject.roles?.includes("admin")) {
    try { requireStepUp(context); return true; } catch { return false; }
  }
  return false;
}

// ============================================================================
// AUTHENTICATION LEVEL: CRITICAL
// Use for: finance, healthcare, government, infrastructure admin.
// Covers: fail-closed enforcement, phishing-resistant MFA gate, tamper-evident
//         audit log, KMS-backed signing, just-in-time privileged access with
//         four-eyes approval, break-glass.
// THIS IS A SKELETON. Production use requires HSM/KMS, WORM log storage,
// independent security review, pen testing, and compliance sign-off.
// ============================================================================

interface StrongClaims extends StepUpClaims { sub: string; amr?: string[] }

// Adjust to the amr values your IdP emits for hardware-bound/FIDO2 factors
const PHISHING_RESISTANT_AMR: ReadonlySet<string> = new Set(["hwk", "fido"]);

export function requirePhishingResistantMfa(claims: StrongClaims): void {
  if (!(claims.amr ?? []).some((m) => PHISHING_RESISTANT_AMR.has(m))) {
    throw new Error("phishing_resistant_mfa_required");
  }
}

interface AuditEntry {
  ts: number; actor: string; event: string; outcome: string;
  details: Record<string, unknown>; prevHash: string; hash: string;
}

/**
 * Hash-chained, append-only log. Also ship every entry off-host in real time
 * to WORM storage/SIEM so admins cannot rewrite history. NEVER log secrets.
 */
export class AuditLog {
  readonly entries: AuditEntry[] = [];

  static #digest(prev: string, e: Omit<AuditEntry, "hash">): string {
    return sha256(`${prev}|${e.ts}|${e.actor}|${e.event}|${e.outcome}|${JSON.stringify(e.details)}`);
  }

  append(actor: string, event: string, outcome: string, details: Record<string, unknown> = {}): void {
    const prevHash = this.entries.at(-1)?.hash ?? "GENESIS";
    const partial = { ts: Date.now(), actor, event, outcome, details, prevHash };
    this.entries.push({ ...partial, hash: AuditLog.#digest(prevHash, partial) });
  }

  verifyChain(): boolean {
    let prev = "GENESIS";
    for (const e of this.entries) {
      if (e.prevHash !== prev || e.hash !== AuditLog.#digest(prev, e)) return false;
      prev = e.hash;
    }
    return true;
  }
}

export const AUDIT = new AuditLog();

/**
 * Implement with AWS KMS / GCP KMS / Azure Key Vault / HSM.
 * App code never touches private key material.
 */
export interface Signer {
  readonly keyId: string;
  sign(payload: Uint8Array): Promise<Uint8Array>;
}

/** Any error, timeout, or unknown state = DENY, and it is audited. */
export const failClosed =
  <A extends unknown[], R>(actionName: string, fn: (claims: StrongClaims, ...args: A) => Promise<R>) =>
  async (claims: StrongClaims, ...args: A): Promise<R> => {
    const actor = claims?.sub ?? "unknown";
    try {
      const result = await fn(claims, ...args);
      AUDIT.append(actor, actionName, "allowed");
      return result;
    } catch (err) {
      AUDIT.append(actor, actionName, "denied", { reason: (err as Error).name });
      throw new Error("Denied");
    }
  };

interface PrivilegedGrant {
  requester: string; role: string; reason: string; ttlMs: number;
  approvedBy: string | null; expiresAt: number | null;
}

const privilegedGrants = new Map<string, PrivilegedGrant>(); // replace with durable, access-controlled store

/** Just-in-time access: no standing admin. Short TTL, reason required. */
export function requestPrivilegedGrant(
  requester: string, role: string, reason: string, ttlMs = 60 * 60 * 1000,
): string {
  if (!reason.trim()) throw new Error("A reason is required");
  const id = crypto.randomUUID();
  privilegedGrants.set(id, { requester, role, reason, ttlMs, approvedBy: null, expiresAt: null });
  AUDIT.append(requester, "privileged_grant_requested", "pending", { role });
  return id;
}

/** Four-eyes: approver must differ from requester and use strong MFA. */
export function approvePrivilegedGrant(grantId: string, approverClaims: StrongClaims): void {
  requirePhishingResistantMfa(approverClaims);
  const g = privilegedGrants.get(grantId);
  if (!g) throw new Error("Unknown grant");
  if (approverClaims.sub === g.requester) throw new Error("Requester cannot approve their own grant");
  g.approvedBy = approverClaims.sub;
  g.expiresAt = Date.now() + g.ttlMs; // auto-expires
  AUDIT.append(approverClaims.sub, "privileged_grant_approved", "allowed", { grantId });
}

export const hasActiveGrant = (userId: string, role: string): boolean =>
  [...privilegedGrants.values()].some(
    (g) => g.requester === userId && g.role === role && g.expiresAt !== null && g.expiresAt > Date.now(),
  );

/**
 * Emergency account. Credentials live offline on a hardware key.
 * Every use MUST page the security team and be reviewed afterward.
 */
export function breakGlassLogin(accountId: string, sourceIp: string): void {
  AUDIT.append(accountId, "BREAK_GLASS_USED", "alert", { ip: sourceIp });
  // TODO: trigger paging/alerting integration here (PagerDuty, SIEM, etc.)
}

export const dangerousAdminAction = failClosed(
  "delete_production_database",
  async (claims: StrongClaims, target: string): Promise<string> => {
    requirePhishingResistantMfa(claims);
    requireStepUp(claims, { maxAgeSeconds: 120 });
    if (!hasActiveGrant(claims.sub, "db_admin")) throw new Error("No active privileged grant");
    return `Action executed on ${target}`;
  },
);