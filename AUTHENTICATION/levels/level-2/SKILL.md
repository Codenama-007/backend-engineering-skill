---
name: auth-standard
description: Implement production-grade authentication for typical web apps, SaaS products, SPAs, and mobile-backed APIs, including JWT access/refresh tokens, email verification, password reset, role-based access control (RBAC), social login (Google/GitHub OAuth), optional TOTP 2FA, and CSRF/rate-limit protections. Use whenever the user mentions JWT, refresh tokens, roles, admin vs. user, forgot password, verify email, "sign in with Google", or API authentication for a real product. For simple session login use auth-basic; for SSO/SAML/passkeys/multi-tenant use auth-advanced; for regulated or high-stakes systems use auth-critical.
---

# Standard (Moderate-Level) Authentication

Goal: a secure, maintainable auth system suitable for a real product with real users and ordinary risk.

## Prerequisites

Everything in `auth-basic` still applies (Argon2id/bcrypt hashing, generic errors, HTTPS, parameterized queries, rate limiting). This skill adds capabilities on top.

## Choose the Session Strategy First

| Client | Recommended approach |
|---|---|
| Server-rendered web app | Server sessions + cookie (stay with auth-basic) |
| SPA on same site as API | Session cookie, or short-lived JWT in an HttpOnly cookie |
| Mobile app / third-party API clients | Short-lived JWT access token + rotating refresh token |

Do not use JWTs just because they are popular. Use them when stateless verification across services or non-browser clients is actually needed.

## Token Design (when using JWT)

- **Access token:** 5-15 minutes. Claims: `sub`, `iat`, `exp`, `iss`, `aud`, `jti`, minimal role info. Never put PII or secrets inside.
- **Signing:** RS256/ES256 (asymmetric) preferred; HS256 only with a strong secret (32+ random bytes) in a single-service setup. **Explicitly pin the allowed algorithm** on verification. Reject `alg: none`.
- **Refresh token:** opaque random string (not a JWT), stored **hashed** in the DB with `user_id`, `device`, `expires_at`, `revoked_at`, `family_id`.
- **Rotation:** every refresh issues a new refresh token and invalidates the old one. If an old token is reused, revoke the entire family (theft signal).
- **Browser storage:** refresh token in an `HttpOnly; Secure; SameSite` cookie. Never in `localStorage`. Keep the access token in memory.
- **Logout:** revoke the refresh token server-side; clear cookies.

## Required Features

### Registration and Email Verification
- Create the user as `unverified`; send a single-use verification link with a random token (stored hashed, expires in 24h).
- Block sensitive actions until verified.

### Password Reset
- Always respond "If that email exists, we sent a link" (prevents account enumeration).
- Random single-use token, stored hashed, expires in 15-60 minutes.
- On success: set the new password, invalidate the token, **revoke all sessions/refresh tokens**, notify the user by email.

### Password Policy
- Minimum 12 characters recommended, allow up to 64+, allow all characters and paste.
- Check against a breached-password list (e.g., HIBP k-anonymity API). Skip arbitrary complexity rules and forced periodic rotation.

### Role-Based Access Control
- Roles in the DB (`user`, `admin`, etc.), mapped to permissions.
- **Enforce on the server for every request**, never rely on hidden UI.
- Check **object-level ownership** too (`resource.owner_id == current_user.id`), not just role. This prevents IDOR.
- Default deny.

### Social Login (OAuth 2.0 / OIDC)
- Use the Authorization Code flow with **PKCE** and a random `state` parameter. Validate `nonce` for OIDC.
- Use a maintained library (Auth.js, Passport, Authlib, Spring Security OAuth).
- Match provider accounts by the stable provider `sub`, not by email alone. Only auto-link by email if the provider asserts it is verified.

### Optional TOTP 2FA
- Standard TOTP (RFC 6238) via a vetted library; store the secret encrypted at rest.
- Issue 8-10 single-use recovery codes, stored hashed.
- Rate-limit code attempts.

## Abuse and Attack Protections

- **Rate limiting:** per IP and per account on login, reset, verify, and 2FA endpoints. Add exponential backoff or temporary lockout (avoid permanent lockout, which enables denial of service).
- **CSRF:** required for cookie-authenticated state-changing requests (SameSite plus CSRF token or custom header check).
- **CORS:** explicit origin allowlist, never `*` with credentials.
- **Security headers:** `Strict-Transport-Security`, `X-Content-Type-Options`, a sensible CSP.
- **Timing safety:** use constant-time comparison for tokens; do equal work for unknown users (hash a dummy password).

## Data Model Outline

Plan for these tables: **users** (email, verification timestamp, password hash, role, encrypted TOTP secret), **refresh tokens** (hashed token, family ID, device info, expiry, revocation time), **one-time tokens** (purpose, hashed token, expiry, used time), **OAuth accounts** (provider, provider subject ID), and an **audit log** (event, IP, user agent, timestamp).

## Logging

Log (without secrets): login success/failure, password change, reset requested/completed, role change, token reuse detected, 2FA enrolled/disabled. Never log passwords, tokens, or reset links.

## Testing Requirements

Write tests for: wrong password, expired token, reused refresh token, tampered JWT, wrong `aud`/`iss`, `alg: none`, access to another user's resource, reset-token reuse, unverified-user restrictions.

## Pre-Delivery Checklist

- [ ] Access tokens short-lived; algorithm pinned
- [ ] Refresh tokens opaque, hashed, rotated, revocable
- [ ] No tokens in `localStorage`
- [ ] Reset and verify tokens single-use, hashed, expiring
- [ ] RBAC plus ownership checks on the server
- [ ] OAuth uses PKCE and `state`
- [ ] Rate limits and CSRF/CORS configured
- [ ] Audit logging in place
- [ ] Auth-specific tests pass

## Escalation

Move to `auth-advanced` for enterprise SSO, passkeys, multi-tenancy, service-to-service auth, or fine-grained policy. Move to `auth-critical` for financial, health, government, or admin-of-infrastructure systems.