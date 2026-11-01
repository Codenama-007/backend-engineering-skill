---
name: auth-advanced
description: Design and implement advanced authentication and authorization architecture for complex projects, including enterprise SSO (SAML/OIDC), acting as an OAuth2/OIDC identity provider, passkeys/WebAuthn, MFA policies, multi-tenant isolation, service-to-service auth (mTLS, client credentials, workload identity), JWKS key rotation, device/session management, step-up authentication, and fine-grained authorization (ABAC/ReBAC/policy engines). Use whenever the user mentions SSO, SAML, Okta, Entra ID, Auth0, Keycloak, passkeys, WebAuthn, multi-tenant, microservices auth, API gateway auth, scopes/claims design, or "advanced auth". For simpler needs use auth-basic or auth-standard; for regulated/high-assurance systems also apply auth-critical.
---

# Advanced Authentication Architecture

Goal: a well-reasoned, scalable identity layer. Spend effort on **design decisions first**, code second.

## Step 0: Build vs. Buy Decision (Always Do First)

Before writing code, state a recommendation:

- **Buy/adopt (default for most teams):** Auth0, Okta, Entra ID, Cognito, Clerk, WorkOS, Keycloak, Ory, Authentik. Faster, battle-tested, handles SAML quirks.
- **Build in-house only if** there are hard requirements (data residency, custom flows, cost at scale) **and** the team can own security patching long-term.
- Never implement SAML signature validation, OIDC token validation, or WebAuthn ceremony parsing from scratch. Use maintained libraries.

## Step 1: Gather Requirements

Ask or infer, then document:

1. Who are the principals? (humans, services, devices, third-party apps)
2. How many tenants, and do enterprise customers bring their own IdP?
3. Required assurance level, MFA policy, and any compliance regime
4. Client types (SPA, native, server, CLI, IoT)
5. Latency/offline constraints on token validation
6. Revocation requirements (how fast must access end?)

## Core Patterns

### Federation (SSO)
- **OIDC** preferred for new integrations; **SAML 2.0** for legacy enterprise IdPs.
- Per-tenant IdP configuration (issuer, client ID, metadata URL, domain mapping).
- Just-in-time provisioning plus **SCIM** for lifecycle (deprovision users when they leave the customer's IdP).
- SAML: validate signature on the correct element, enforce `Audience`, `Recipient`, `NotOnOrAfter`, `InResponseTo`; defend against XML signature wrapping; disable external entities.
- OIDC: validate `iss`, `aud`, `exp`, `nonce`, signature via JWKS; use Authorization Code + PKCE only (no implicit flow).

### Acting as an Authorization Server
- Support Authorization Code + PKCE, Client Credentials, Refresh Token (rotating). Skip password grant.
- Exact-match redirect URI validation; no wildcards.
- Publish `/.well-known/openid-configuration` and a JWKS endpoint.
- **Key rotation:** asymmetric keys with `kid`, overlap old and new keys during rotation, keys held in KMS/HSM where possible.
- Consider sender-constrained tokens (DPoP or mTLS-bound) for high-value APIs.

### Passwordless and Phishing-Resistant Credentials
- **Passkeys/WebAuthn** as a first-class login method; keep a secure recovery path (recovery is the usual weak point).
- Support multiple credentials per user; label and allow removal.
- Use a maintained WebAuthn library (e.g., SimpleWebAuthn, py_webauthn, webauthn4j). Enforce `rpId`/origin checks and signature counter handling.

### MFA and Step-Up
- Policy-driven: per tenant, per role, per risk signal.
- **Step-up auth** for sensitive actions (change email, add payout account, delete org): require a fresh authentication (`auth_time` within N minutes, `acr` claim).
- Rank factors: passkey/security key > TOTP > push > SMS (SMS only as fallback, never for admins).

### Multi-Tenancy
- `tenant_id` is a first-class claim and column; **every query is tenant-scoped** (enforce with row-level security or a mandatory query layer, not developer discipline).
- Tenant-specific auth settings (SSO enforced, allowed domains, MFA required).
- Prevent cross-tenant account confusion: identity key = `(tenant, issuer, sub)`.

### Service-to-Service
- Prefer workload identity (SPIFFE/SPIRE, cloud IAM roles, Kubernetes service accounts) over long-lived shared secrets.
- mTLS inside the mesh; OAuth2 client credentials with narrow scopes otherwise.
- Gateway validates tokens at the edge; services still **verify audience and scope** (don't trust the network).
- Propagate user context with signed tokens (token exchange, RFC 8693), not spoofable headers.

### Authorization
- Separate **authentication** (who) from **authorization** (what). Keep the authz decision in one place.
- Choose a model deliberately:
  - **RBAC** for coarse roles
  - **ABAC** for attribute-driven rules (department, region, data classification)
  - **ReBAC** (Zanzibar-style: OpenFGA, SpiceDB) for sharing/hierarchies
  - Policy engines: OPA/Rego, Cedar
- Keep scopes (what a client may ask) distinct from permissions (what a user may do). Effective access is the intersection.

### Sessions and Revocation
- Short access tokens plus rotating refresh tokens, with refresh-token reuse detection.
- Server-side session/device table: list active sessions, "sign out everywhere", per-device revocation.
- For instant revocation: token introspection, revocation lists keyed by `jti`/`sid`, or back-channel logout (OIDC).

## Threat Model (Include in Deliverable)

Cover at minimum: credential stuffing, phishing, token theft/replay, session fixation, refresh-token theft, confused deputy, open redirect, IDOR/BOLA, cross-tenant leakage, SAML/JWT validation bypass, account takeover via recovery flow, malicious IdP in a tenant.

## Deliverables Claude Should Produce

1. A short **architecture decision record**: chosen approach, alternatives, trade-offs
2. A **sequence diagram** (Mermaid) for each main flow (login, refresh, SSO, step-up)
3. Data model and token/claim schema
4. Implementation using vetted libraries
5. **Test plan** covering negative cases (forged, expired, wrong-audience, cross-tenant, replayed tokens)
6. Operational notes: key rotation runbook, monitoring, alerting

## Observability

Structured audit events with correlation IDs: auth success/failure, MFA enroll/reset, SSO config changes, token reuse, privilege changes, impossible-travel flags. Alert on spikes. Never log tokens or secrets.

## Pre-Delivery Checklist

- [ ] Build-vs-buy decision documented
- [ ] All token validation pins issuer, audience, algorithm, expiry
- [ ] PKCE everywhere; exact redirect matching
- [ ] Key rotation procedure exists and was tested
- [ ] Tenant isolation enforced at the data layer
- [ ] Step-up defined for sensitive actions
- [ ] Recovery flows reviewed as attack surface
- [ ] Revocation path defined and tested
- [ ] Threat model and negative tests included

## Escalation

If the system handles money movement, health/government data, infrastructure admin, or has regulatory obligations, also apply `auth-critical` and recommend an independent security review.