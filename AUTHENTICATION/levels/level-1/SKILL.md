---
name: auth-basic
description: Implement basic username/password authentication with server-side sessions for small apps, prototypes, hobby projects, internal tools, tutorials, and MVPs. Use whenever the user asks for a simple login, signup, register, logout, "add authentication", or "protect this page" and has NOT mentioned JWTs, OAuth, SSO, MFA, roles, compliance, or high-security needs. If those appear, use auth-standard, auth-advanced, or auth-critical instead.
---

# Basic Authentication

Goal: a correct, safe, minimal login system. Simple does not mean insecure. Follow every rule below even in a prototype.

## Scope

**In scope:** register, login, logout, protected routes, current-user lookup, simple "logged in vs. not" checks.

**Out of scope (escalate to a higher skill):** JWT/refresh tokens, social login, roles/permissions, MFA, email flows, multi-tenant, regulated data.

## Default Architecture

- **Server-side sessions** stored in memory/DB/Redis, referenced by a random session ID in a cookie.
- Prefer the framework's built-in auth/session library (Django auth, Rails `has_secure_password`, Laravel Auth, Passport/Auth.js, Spring Security, ASP.NET Identity). Do not hand-roll when a vetted option exists.

## Non-Negotiable Rules

1. **Hash passwords** with Argon2id (preferred), bcrypt, or scrypt. Never store plaintext, never use MD5/SHA-1/SHA-256 alone, never encrypt reversibly.
2. **Never roll your own crypto.** Use library functions for hashing, random tokens, and comparison.
3. **Session cookie flags:** `HttpOnly`, `Secure` (HTTPS), `SameSite=Lax`. Session IDs must be long and random (from a CSPRNG, 128+ bits).
4. **Regenerate the session ID on login** to prevent session fixation. Destroy the session fully on logout.
5. **Generic error messages:** "Invalid email or password", never "user not found" vs "wrong password".
6. **Parameterized queries only.** No string-built SQL.
7. **HTTPS everywhere** outside local development.
8. **Secrets in environment variables**, never in source control.

## Implementation Steps

1. **User model:** `id`, `email` (unique, lowercased), `password_hash`, `created_at`.
2. **Register:** validate email format, enforce minimum password length of 8+ (prefer 12+; allow long passphrases, don't force odd composition rules), hash, store, then log in.
3. **Login:** look up by normalized email, verify hash with the library's constant-time verify, regenerate session, store `user_id` in session.
4. **Logout:** destroy server-side session, clear cookie. Use POST, not GET.
5. **Auth middleware:** read the session, load the user, return 401 (API) or redirect to login (pages) if missing.
6. **Basic rate limiting** on login (e.g., 5-10 attempts per minute per IP + account).
7. **CSRF protection** for any form-based state change (framework default token or SameSite plus a token).

## Do Not

- Put tokens or passwords in URLs, logs, or `localStorage`.
- Log request bodies on auth routes.
- Email users their password.
- Invent custom "encryption" or "obfuscation" schemes.

## Pre-Delivery Checklist

- [ ] Passwords hashed with Argon2id/bcrypt/scrypt
- [ ] Cookie is HttpOnly + Secure + SameSite
- [ ] Session regenerated on login, destroyed on logout
- [ ] Generic login errors
- [ ] Login rate-limited
- [ ] Protected routes actually return 401/redirect when logged out (test it)
- [ ] No secrets committed

## When to Tell the User to Upgrade

Mention moving to `auth-standard` if the project adds roles, password reset, email verification, a mobile/SPA client, or social login.