"""
Authentication templates: Beginner -> Intermediate -> Advanced -> Critical (Python)

Install: pip install argon2-cffi pyjwt[crypto] pyotp

IMPORTANT
- Framework-agnostic building blocks. In-memory dicts stand in for your
  database/Redis. Replace them before real use.
- Each section is labeled with the level it belongs to. Higher levels build on
  the lower ones: use only the sections your project actually needs.
- The CRITICAL section is a starting skeleton, NOT a compliant implementation.
  It requires human security review, pen testing, and compliance sign-off.
"""

import base64
import hashlib
import hmac
import os
import secrets
import time
from functools import wraps
from typing import Any, Callable, Optional, Protocol

import jwt  # PyJWT
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jwt import PyJWKClient

# ============================================================================
# AUTHENTICATION LEVEL: BEGINNER
# Use for: prototypes, MVPs, internal tools.
# Covers: password hashing, server-side sessions, generic errors, rate limiting.
# ============================================================================

ph = PasswordHasher()  # Argon2id by default
USERS: dict[str, dict] = {}      # email -> user record (replace with DB)
SESSIONS: dict[str, dict] = {}   # session_id -> {user_id, expires_at}
ATTEMPTS: dict[str, list[float]] = {}  # key -> timestamps (replace with Redis)

# Hash used to keep timing equal when the email does not exist
DUMMY_HASH = ph.hash("dummy-password-for-timing")

SESSION_TTL = 60 * 60 * 24 * 7  # 7 days

# Send these flags when setting the cookie in your framework
SESSION_COOKIE_OPTIONS = {
    "httponly": True,
    "secure": True,      # HTTPS only
    "samesite": "Lax",
    "max_age": SESSION_TTL,
}


def normalize_email(email: str) -> str:
    return email.strip().lower()


def rate_limited(key: str, limit: int = 5, window: int = 60) -> bool:
    """Allow `limit` attempts per `window` seconds per key (IP and/or email)."""
    now = time.time()
    recent = [t for t in ATTEMPTS.get(key, []) if now - t < window]
    recent.append(now)
    ATTEMPTS[key] = recent
    return len(recent) > limit


def register(email: str, password: str) -> dict:
    email = normalize_email(email)
    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters")
    if email in USERS:
        raise ValueError("Unable to register with those details")  # no enumeration
    user = {
        "id": secrets.token_hex(16),
        "email": email,
        "password_hash": ph.hash(password),
        "role": "user",
        "verified": False,
    }
    USERS[email] = user
    return user


def login(email: str, password: str, ip: str) -> str:
    """Returns a NEW session id. Set it in the cookie using SESSION_COOKIE_OPTIONS."""
    email = normalize_email(email)
    if rate_limited(f"login:{ip}") or rate_limited(f"login:{email}"):
        raise PermissionError("Too many attempts. Try again later.")

    user = USERS.get(email)
    try:
        ph.verify(user["password_hash"] if user else DUMMY_HASH, password)
        valid = user is not None
    except VerifyMismatchError:
        valid = False
    if not valid:
        raise PermissionError("Invalid email or password")  # generic on purpose

    # Always issue a fresh session id on login (prevents session fixation)
    session_id = secrets.token_urlsafe(32)
    SESSIONS[session_id] = {"user_id": user["id"], "expires_at": time.time() + SESSION_TTL}
    return session_id


def get_session_user(session_id: Optional[str]) -> Optional[dict]:
    session = SESSIONS.get(session_id or "")
    if not session or session["expires_at"] < time.time():
        SESSIONS.pop(session_id or "", None)
        return None
    return next((u for u in USERS.values() if u["id"] == session["user_id"]), None)


def logout(session_id: str) -> None:
    SESSIONS.pop(session_id, None)  # destroy server-side, then clear the cookie


# ============================================================================
# AUTHENTICATION LEVEL: INTERMEDIATE
# Use for: production web/mobile apps and SaaS.
# Covers: JWT access tokens, rotating refresh tokens, one-time tokens
#         (verify email / password reset), RBAC with ownership checks, TOTP 2FA.
# ============================================================================

ISSUER = "https://auth.example.com"
AUDIENCE = "example-api"
ACCESS_TTL = 10 * 60                 # 10 minutes
REFRESH_TTL = 60 * 60 * 24 * 30      # 30 days
JWT_ALG = "RS256"                    # pin the algorithm explicitly
JWT_PRIVATE_KEY = os.environ.get("JWT_PRIVATE_KEY", "")  # PEM from secret manager
JWT_PUBLIC_KEY = os.environ.get("JWT_PUBLIC_KEY", "")
JWT_KEY_ID = os.environ.get("JWT_KEY_ID", "key-1")

REFRESH_TOKENS: dict[str, dict] = {}   # sha256(token) -> record
ONE_TIME_TOKENS: dict[str, dict] = {}  # sha256(token) -> record


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def issue_access_token(user: dict, extra_claims: Optional[dict] = None) -> str:
    now = int(time.time())
    claims = {
        "sub": user["id"],
        "role": user["role"],
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + ACCESS_TTL,
        "jti": secrets.token_hex(16),
        **(extra_claims or {}),
    }
    return jwt.encode(claims, JWT_PRIVATE_KEY, algorithm=JWT_ALG, headers={"kid": JWT_KEY_ID})


def verify_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        JWT_PUBLIC_KEY,
        algorithms=[JWT_ALG],  # never accept the token's own "alg" header
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"require": ["exp", "iat", "sub", "iss", "aud", "jti"]},
    )


def issue_refresh_token(user_id: str, family_id: Optional[str] = None) -> str:
    raw = secrets.token_urlsafe(48)  # opaque, NOT a JWT
    REFRESH_TOKENS[sha256(raw)] = {  # store only the hash
        "user_id": user_id,
        "family_id": family_id or secrets.token_hex(16),
        "expires_at": time.time() + REFRESH_TTL,
        "revoked": False,
    }
    return raw


def rotate_refresh_token(raw: str) -> tuple[str, str]:
    """Returns (new_access_token, new_refresh_token). Detects token theft via reuse."""
    record = REFRESH_TOKENS.get(sha256(raw))
    if not record or record["expires_at"] < time.time():
        raise PermissionError("Invalid refresh token")
    if record["revoked"]:
        # A used token came back: assume theft, kill the whole token family
        for r in REFRESH_TOKENS.values():
            if r["family_id"] == record["family_id"]:
                r["revoked"] = True
        raise PermissionError("Refresh token reuse detected")
    record["revoked"] = True
    user = next(u for u in USERS.values() if u["id"] == record["user_id"])
    return issue_access_token(user), issue_refresh_token(user["id"], record["family_id"])


def create_one_time_token(user_id: str, purpose: str, ttl: int = 30 * 60) -> str:
    """purpose: 'verify_email' or 'reset_password'. Email the raw token as a link."""
    raw = secrets.token_urlsafe(32)
    ONE_TIME_TOKENS[sha256(raw)] = {
        "user_id": user_id, "purpose": purpose,
        "expires_at": time.time() + ttl, "used": False,
    }
    return raw


def consume_one_time_token(raw: str, purpose: str) -> str:
    record = ONE_TIME_TOKENS.get(sha256(raw))
    if (not record or record["used"] or record["purpose"] != purpose
            or record["expires_at"] < time.time()):
        raise PermissionError("Invalid or expired token")
    record["used"] = True  # single use
    return record["user_id"]


def revoke_all_user_tokens(user_id: str) -> None:
    """Call after password reset/change so old sessions and tokens stop working."""
    for r in REFRESH_TOKENS.values():
        if r["user_id"] == user_id:
            r["revoked"] = True
    for sid in [s for s, v in SESSIONS.items() if v["user_id"] == user_id]:
        SESSIONS.pop(sid)


ROLE_PERMISSIONS = {
    "user": {"post:read", "post:create"},
    "admin": {"post:read", "post:create", "post:delete", "user:manage"},
}


def authorize(claims: dict, permission: str, resource_owner_id: Optional[str] = None) -> bool:
    """Default deny. Checks role permission AND object ownership (prevents IDOR)."""
    if permission not in ROLE_PERMISSIONS.get(claims.get("role", ""), set()):
        return False
    if resource_owner_id and claims["role"] != "admin":
        return claims["sub"] == resource_owner_id
    return True


def require_permission(permission: str) -> Callable:
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(claims: dict, *args: Any, **kwargs: Any):
            if not authorize(claims, permission):
                raise PermissionError("Forbidden")
            return fn(claims, *args, **kwargs)
        return wrapper
    return decorator


def verify_totp(secret: str, code: str) -> bool:
    """TOTP 2FA. Rate-limit this endpoint and store `secret` encrypted at rest."""
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def generate_recovery_codes(n: int = 10) -> tuple[list[str], list[str]]:
    """Show raw codes to the user once; store only the hashes."""
    raw = [secrets.token_hex(5) for _ in range(n)]
    return raw, [sha256(c) for c in raw]


# ============================================================================
# AUTHENTICATION LEVEL: ADVANCED
# Use for: enterprise SSO, multi-tenant, step-up auth, fine-grained authz.
# Covers: OIDC PKCE + ID token validation, tenant-scoped identity,
#         step-up authentication, attribute-based access control (ABAC).
# Prefer a vetted IdP/library for full flows; these are the core checks.
# ============================================================================


def generate_pkce() -> tuple[str, str]:
    """Returns (code_verifier, code_challenge). Keep verifier server-side/session."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


def verify_oidc_id_token(id_token: str, jwks_url: str, issuer: str,
                         client_id: str, expected_nonce: str) -> dict:
    """Validate signature (via JWKS), issuer, audience, expiry, and nonce."""
    signing_key = PyJWKClient(jwks_url).get_signing_key_from_jwt(id_token)
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=["RS256", "ES256"],
        audience=client_id,
        issuer=issuer,
        options={"require": ["exp", "iat", "sub", "iss", "aud"]},
    )
    if not hmac.compare_digest(claims.get("nonce", ""), expected_nonce):
        raise PermissionError("Invalid nonce")
    return claims


def identity_key(tenant_id: str, issuer: str, subject: str) -> str:
    """Identity = (tenant, issuer, sub). Never match accounts on email alone."""
    return f"{tenant_id}|{issuer}|{subject}"


def require_step_up(claims: dict, max_age_seconds: int = 300,
                    required_acr: Optional[str] = None) -> None:
    """Demand recent authentication before sensitive actions (change email, payouts)."""
    auth_time = claims.get("auth_time")
    if auth_time is None or time.time() - auth_time > max_age_seconds:
        raise PermissionError("step_up_required")
    if required_acr and claims.get("acr") != required_acr:
        raise PermissionError("step_up_required")


def evaluate_policy(subject: dict, action: str, resource: dict, context: dict) -> bool:
    """ABAC decision point. Default deny; every rule must be explicit."""
    if subject.get("tenant_id") != resource.get("tenant_id"):
        return False  # hard tenant isolation
    if action == "read" and resource.get("classification") == "public":
        return True
    if action == "read" and subject.get("department") == resource.get("department"):
        return True
    if action == "write" and resource.get("owner_id") == subject.get("id"):
        return True
    if action == "delete" and "admin" in subject.get("roles", []):
        try:
            require_step_up(context)  # sensitive action needs fresh auth
            return True
        except PermissionError:
            return False
    return False


# ============================================================================
# AUTHENTICATION LEVEL: CRITICAL
# Use for: finance, healthcare, government, infrastructure admin.
# Covers: fail-closed enforcement, phishing-resistant MFA gate, tamper-evident
#         audit log, KMS-backed signing, just-in-time privileged access with
#         four-eyes approval, break-glass.
# THIS IS A SKELETON. Production use requires HSM/KMS, WORM log storage,
# independent security review, pen testing, and compliance sign-off.
# ============================================================================

# Adjust to the amr values your IdP emits for hardware-bound/FIDO2 factors
PHISHING_RESISTANT_AMR = {"hwk", "fido"}


def require_phishing_resistant_mfa(claims: dict) -> None:
    if not PHISHING_RESISTANT_AMR.intersection(claims.get("amr", [])):
        raise PermissionError("phishing_resistant_mfa_required")


class AuditLog:
    """Hash-chained, append-only log. Also ship every entry off-host in real time
    to WORM storage/SIEM so admins cannot rewrite history. NEVER log secrets."""

    def __init__(self) -> None:
        self.entries: list[dict] = []

    def append(self, actor: str, event: str, outcome: str, details: Optional[dict] = None) -> None:
        prev_hash = self.entries[-1]["hash"] if self.entries else "GENESIS"
        body = f"{prev_hash}|{time.time()}|{actor}|{event}|{outcome}|{details or {}}"
        self.entries.append({
            "ts": time.time(), "actor": actor, "event": event,
            "outcome": outcome, "details": details or {},
            "prev_hash": prev_hash, "hash": sha256(body),
        })

    def verify_chain(self) -> bool:
        prev = "GENESIS"
        for e in self.entries:
            body = f"{prev}|{e['ts']}|{e['actor']}|{e['event']}|{e['outcome']}|{e['details']}"
            if e["prev_hash"] != prev or not hmac.compare_digest(e["hash"], sha256(body)):
                return False
            prev = e["hash"]
        return True


AUDIT = AuditLog()


class Signer(Protocol):
    """Implement with AWS KMS / GCP KMS / Azure Key Vault / HSM.
    App code never touches private key material."""
    key_id: str
    def sign(self, payload: bytes) -> bytes: ...


def fail_closed(action_name: str) -> Callable:
    """Any error, timeout, or unknown state = DENY, and it is audited."""
    def decorator(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapper(claims: dict, *args: Any, **kwargs: Any):
            actor = claims.get("sub", "unknown")
            try:
                result = fn(claims, *args, **kwargs)
                AUDIT.append(actor, action_name, "allowed")
                return result
            except Exception as exc:  # noqa: BLE001 - deliberate catch-all
                AUDIT.append(actor, action_name, "denied", {"reason": type(exc).__name__})
                raise PermissionError("Denied") from None
        return wrapper
    return decorator


PRIVILEGED_GRANTS: dict[str, dict] = {}  # replace with durable, access-controlled store


def request_privileged_grant(requester: str, role: str, reason: str, ttl: int = 3600) -> str:
    """Just-in-time access: no standing admin. Short TTL, reason required."""
    if not reason.strip():
        raise ValueError("A reason is required")
    grant_id = secrets.token_hex(16)
    PRIVILEGED_GRANTS[grant_id] = {
        "requester": requester, "role": role, "reason": reason,
        "ttl": ttl, "approved_by": None, "expires_at": None,
    }
    AUDIT.append(requester, "privileged_grant_requested", "pending", {"role": role})
    return grant_id


def approve_privileged_grant(grant_id: str, approver_claims: dict) -> None:
    """Four-eyes: approver must differ from requester and use strong MFA."""
    require_phishing_resistant_mfa(approver_claims)
    grant = PRIVILEGED_GRANTS[grant_id]
    if approver_claims["sub"] == grant["requester"]:
        raise PermissionError("Requester cannot approve their own grant")
    grant["approved_by"] = approver_claims["sub"]
    grant["expires_at"] = time.time() + grant["ttl"]  # auto-expires
    AUDIT.append(approver_claims["sub"], "privileged_grant_approved", "allowed", {"grant": grant_id})


def has_active_grant(user_id: str, role: str) -> bool:
    now = time.time()
    return any(
        g["requester"] == user_id and g["role"] == role
        and g["expires_at"] and g["expires_at"] > now
        for g in PRIVILEGED_GRANTS.values()
    )


def break_glass_login(account_id: str, source_ip: str) -> None:
    """Emergency account. Credentials live offline on a hardware key.
    Every use MUST page the security team and be reviewed afterward."""
    AUDIT.append(account_id, "BREAK_GLASS_USED", "alert", {"ip": source_ip})
    # TODO: trigger paging/alerting integration here (PagerDuty, SIEM, etc.)


@fail_closed("delete_production_database")
def dangerous_admin_action(claims: dict, target: str) -> str:
    require_phishing_resistant_mfa(claims)
    require_step_up(claims, max_age_seconds=120)
    if not has_active_grant(claims["sub"], "db_admin"):
        raise PermissionError("No active privileged grant")
    return f"Action executed on {target}"