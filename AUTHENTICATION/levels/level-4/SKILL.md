---
name: auth-critical
description: Guidance for mission-critical, high-assurance authentication where compromise causes severe harm, such as banking and payments, healthcare (HIPAA), government, defense, critical infrastructure, admin/root access to production systems, cryptocurrency custody, or regulated environments (PCI-DSS, SOC 2, ISO 27001, NIST 800-63, FedRAMP, GDPR). Use whenever the user mentions compliance, audit, regulated data, financial transactions, privileged access, zero trust, HSM, break-glass, "must never be breached", or describes a system where an auth failure would be catastrophic. Apply together with auth-advanced. Claude acts as a design aid and reviewer here, not as the final authority.
---

# Mission-Critical Authentication

Goal: assume breach, minimize blast radius, prove what happened. In this tier, **correctness, auditability, and defense in depth outrank speed and convenience.**

## Operating Principles for Claude

1. **Be candid about limits.** Auth code written in a chat is a draft. State clearly that production deployment requires human security review, threat modeling with the team, and independent penetration testing. Do not imply the output is certified or compliant.
2. **Prefer proven components** (managed IdP with compliance attestations, cloud KMS/HSM, vetted libraries) over custom code. Custom cryptography or protocol parsing is prohibited.
3. **Fail closed.** Errors, timeouts, and unknown states deny access.
4. **Stop and ask** when requirements are ambiguous on: assurance level, data classification, regulatory regime, or who can administer the system. Do not guess on these.
5. **No shortcuts in examples.** No hardcoded secrets, disabled TLS verification, or "TODO: add auth" placeholders.

## Step 1: Classify the System

Document before designing:

- **Data and action sensitivity:** what is the worst thing an attacker can do with one account? One admin account?
- **Regulatory map:** e.g., PCI-DSS (cardholder data), HIPAA (PHI), SOX, GDPR, FedRAMP, NIS2, DORA.
- **Target assurance:** map to NIST SP 800-63 **AAL2** (multi-factor, approved crypto) or **AAL3** (hardware-bound, phishing-resistant, verifier-impersonation resistant).
- **Identity proofing level** (IAL) if users are verified in-person or by document.

## Step 2: Mandatory Controls

### Credentials and Factors
- **Phishing-resistant MFA required** for all privileged and sensitive users: FIDO2/WebAuthn security keys or platform passkeys. SMS and email OTP are not acceptable for admins; discouraged for anyone.
- Passwords, if present at all, are one factor only. Argon2id with tuned parameters (memory-hard, benchmarked on production hardware), per-user salt, optional server-side pepper held in KMS/HSM. Breached-password screening on set and periodically.
- **Recovery is an attack path.** Require multi-party or high-friction recovery for privileged accounts (e.g., two-person approval plus out-of-band verification). Log and notify all recovery events.

### Sessions and Tokens
- Short lifetimes (access: minutes; privileged sessions: shorter, with absolute and idle timeouts).
- **Sender-constrained tokens** (DPoP or mTLS-bound) and device binding where supported.
- **Step-up re-authentication** for each high-risk action (wire transfer, key export, permission grant), bound to that transaction, with what-you-see-is-what-you-sign confirmation where feasible.
- Immediate revocation capability: central session store, introspection, back-channel logout, kill-switch per user/tenant/system.
- Cookie flags: `HttpOnly; Secure; SameSite=Strict` plus `__Host-` prefix.

### Cryptographic Key Management
- Signing and encryption keys in **HSM or cloud KMS** (FIPS 140-2/3 validated where required). Application code never sees private key material.
- Documented rotation schedule and emergency rotation runbook; `kid`-based overlap.
- Separation of duties: the people who deploy code cannot export keys.
- Secrets via a secret manager with short-lived, dynamically issued credentials; no long-lived static secrets in env files or CI variables.

### Authorization
- **Zero trust:** authenticate and authorize every request at every hop; no implicit trust from network location.
- **Least privilege and default deny**, expressed as policy-as-code (OPA/Cedar) with version control and review.
- **Just-in-time privileged access** with approval, time-boxed grants, and automatic expiry. No standing admin.
- **Separation of duties / four-eyes** for destructive or financial operations.
- **Break-glass accounts:** offline-stored, hardware-key-protected, alarmed on any use, reviewed after every use.

### Detection and Response
- **Tamper-evident audit logs:** append-only, shipped off-host in real time, hash-chained or written to WORM storage, time-synced. Record who, what, when, from where, outcome, and authorization decision. **Never log secrets, tokens, or full PII.**
- Alerting on: impossible travel, new device plus privileged action, MFA reset, token reuse, privilege escalation, mass failures, break-glass use.
- Automated containment: risk-based lockout, forced re-auth, session kill.
- Tested **incident response runbook** for credential compromise, key compromise, and IdP compromise.

### Platform Hardening
- TLS 1.2+ (prefer 1.3), HSTS preload, certificate pinning only where operationally safe.
- Auth service isolated in its own network segment, minimal dependencies, dedicated deploy pipeline with signed artifacts and SBOM.
- Rate limiting and anomaly-based bot defense; protection against credential stuffing and enumeration (uniform responses and timing).
- Dependency scanning, SAST/DAST, and secret scanning gated in CI.
- Backups of identity data encrypted, access-controlled, and restore-tested.

## Step 3: Required Deliverables

1. **Threat model** (STRIDE or attack trees) covering external attackers, malicious insiders, compromised IdP, compromised admin, and supply chain.
2. **Control mapping** table: requirement (e.g., NIST 800-63B, PCI-DSS 8.x) → implemented control → evidence.
3. **Architecture and data-flow diagrams**, including trust boundaries.
4. **Abuse-case and negative test suite:** forged, replayed, expired, cross-tenant, downgraded-factor, race-condition, and recovery-flow attacks.
5. **Operational runbooks:** key rotation, break-glass, incident response, user offboarding.
6. **Residual risk register** with owners.

## Review Gates (Claude Must State These)

Before this design is considered production-ready, the user should obtain:

- [ ] Peer review by a qualified security engineer
- [ ] Independent penetration test, including auth and recovery flows
- [ ] Compliance/GRC sign-off for the applicable regime
- [ ] Load and failure-mode testing (IdP outage, KMS outage, clock skew)
- [ ] Disaster-recovery exercise for the identity system
- [ ] Ongoing: patch SLAs, periodic access reviews, annual re-test

## Common Critical Failures to Check For

- Standing admin access and shared accounts
- SMS/email fallback silently downgrading strong MFA
- Account recovery that bypasses MFA
- Tokens valid after password change or offboarding
- Missing object-level authorization (BOLA/IDOR) behind a strong login
- Audit logs writable by the same admins they monitor
- Single IdP or KMS with no tested failure plan
- Long-lived service credentials in CI or code

## Response Style in This Tier

Be explicit and structured. State assumptions, list open questions, flag risks plainly, and recommend professional review. A short, correct, caveated answer beats a long confident one.