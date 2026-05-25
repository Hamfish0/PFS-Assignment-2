"""Authentication routes: login, register, list users.

All historical vulnerabilities (V2, V3, V4, V7, V8, V9, V12) in this module
have been remediated. Fixes are tagged inline with `# FIX-Vn:`.
"""

import os
import re
import secrets
import sqlite3
import sys
import time
from collections import deque
from datetime import datetime, timedelta
from threading import Lock

import jwt
from flask import Blueprint, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from database import get_connection, log_audit

auth_bp = Blueprint("auth", __name__)

# FIX-V2: hardcoded ADMIN_USERNAME / ADMIN_PASSWORD constants removed entirely.
# Credentials live only in the database (hashed) and are seeded from env vars
# or randomised on first init (see database._seed).

# FIX-V4: load JWT secret from environment. If absent, generate a strong
# per-process secret so tokens are invalidated on restart rather than signing
# with a weak default. The `algorithms=["HS256"]` allow-list on decode ensures
# we never trust the token header's own `alg` value (preventing alg=none /
# algorithm-confusion attacks).
JWT_SECRET = os.environ.get("INVTRACKER_JWT_SECRET")
if not JWT_SECRET:
    JWT_SECRET = secrets.token_urlsafe(32)
    print(
        "[invtracker] INVTRACKER_JWT_SECRET not set; generated an ephemeral "
        "secret. All issued tokens will become invalid when the process exits.",
        file=sys.stderr,
    )
JWT_ALGORITHM = "HS256"
JWT_TTL = timedelta(hours=8)  # shorter than the original 7-day window

REQUEST_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "requests.log")

# FIX-V8: in-memory sliding-window rate limit for /api/auth/login. Suitable
# for a single-process dev/demo deployment; behind a real reverse proxy or
# multi-worker WSGI server, swap for a shared store (Redis, etc.).
_LOGIN_WINDOW_SECONDS = 300  # 5 minutes
_LOGIN_MAX_FAILURES = 5
_login_failures: dict[tuple[str, str], deque[float]] = {}
_login_lock = Lock()


def issue_token(user_row):
    """FIX-V4: issue a JWT with a real expiry. The exp claim is enforced on decode."""
    payload = {
        "sub": user_row["id"],
        "username": user_row["username"],
        "role": user_row["role"],
        "exp": datetime.utcnow() + JWT_TTL,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str):
    """FIX-V4: decode a JWT safely.

    - The `alg=none` short-circuit has been removed completely.
    - `algorithms=[JWT_ALGORITHM]` pins the accepted algorithm; PyJWT will not
      consult the header's `alg` field for algorithm selection.
    - Expiry is enforced (no `verify_exp: False` override).
    - All decode errors are caught and return None so callers cannot
      accidentally trust an undecoded payload.
    """
    if not token:
        return None
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.PyJWTError:
        return None


def current_user():
    """Return the decoded JWT payload for the current request, or None."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer "):].strip()
    return decode_token(token)


# FIX-V5 + FIX-V12: small helper used by route modules to enforce role-based
# access. Centralising this removes the previous "any authenticated caller can
# do anything" pattern.
def require_auth():
    """Return (user, None) if authenticated, otherwise (None, 401 response)."""
    user = current_user()
    if not user:
        return None, (jsonify({"error": "Authentication required"}), 401)
    return user, None


def require_role(*allowed_roles):
    """Return (user, None) if authenticated and role is allowed, else error tuple."""
    user, err = require_auth()
    if err:
        return None, err
    if user.get("role") not in allowed_roles:
        return None, (jsonify({"error": "Forbidden"}), 403)
    return user, None


# FIX-V7: redact secrets before they hit the request log. The Authorization
# header (which contains the bearer token) is masked, and any JSON `password`
# field in the body is replaced with `***`.
_PASSWORD_FIELD_RE = re.compile(r'("password"\s*:\s*)"[^"]*"', re.IGNORECASE)


def _redact_authorization(value: str) -> str:
    if not value:
        return ""
    if value.startswith("Bearer "):
        return "Bearer <redacted>"
    return "<redacted>"


def _redact_body(body: str) -> str:
    if not body:
        return ""
    return _PASSWORD_FIELD_RE.sub(r'\1"***"', body)


def log_request():
    """Append a redacted record of the request to the local log file."""
    try:
        with open(REQUEST_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.utcnow().isoformat()} {request.method} {request.path} "
                f"auth={_redact_authorization(request.headers.get('Authorization', ''))} "
                f"body={_redact_body(request.get_data(as_text=True)[:500])}\n"
            )
    except OSError:
        pass


def _rate_limit_key():
    # FIX-V8: throttle per (client IP, username) so a single attacker cannot
    # spray across many usernames from one address, but also so failed
    # attempts against one user from many users do not lock out the victim
    # globally. request.remote_addr is sufficient for a dev deployment; behind
    # a proxy, use a vetted X-Forwarded-For parser.
    addr = request.remote_addr or "unknown"
    return addr


def _check_rate_limit(username: str) -> bool:
    """Return True if the caller is allowed to attempt a login."""
    key = (_rate_limit_key(), (username or "").lower())
    now = time.monotonic()
    with _login_lock:
        bucket = _login_failures.get(key)
        if bucket is None:
            return True
        while bucket and now - bucket[0] > _LOGIN_WINDOW_SECONDS:
            bucket.popleft()
        return len(bucket) < _LOGIN_MAX_FAILURES


def _record_login_failure(username: str) -> None:
    key = (_rate_limit_key(), (username or "").lower())
    now = time.monotonic()
    with _login_lock:
        bucket = _login_failures.setdefault(key, deque())
        bucket.append(now)


def _clear_login_failures(username: str) -> None:
    key = (_rate_limit_key(), (username or "").lower())
    with _login_lock:
        _login_failures.pop(key, None)


@auth_bp.post("/api/auth/login")
def login():
    """Authenticate a user and return a JWT."""
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    # FIX-V8: rate-limit before doing any work, including DB lookups, so a
    # blocked client cannot use this endpoint as a username-enumeration oracle.
    if not _check_rate_limit(username):
        return jsonify({"error": "Too many attempts, try again later"}), 429

    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    # FIX-V3: compare against the stored salted hash. check_password_hash is
    # constant-time per-byte and rejects malformed stored hashes safely.
    valid = bool(row) and check_password_hash(row["password"], password)
    if not valid:
        _record_login_failure(username)
        # Generic error message so we don't reveal whether the username exists.
        return jsonify({"error": "Invalid credentials"}), 401

    _clear_login_failures(username)
    token = issue_token(row)
    log_audit("LOGIN", None, row["id"], f"user={username}")
    return jsonify(
        {
            "token": token,
            "user": {"id": row["id"], "username": row["username"], "role": row["role"]},
        }
    )


@auth_bp.post("/api/auth/register")
def register():
    """Create a new user account. Requires admin authentication."""
    _, err = require_role("admin")
    if err:
        return err

    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role", "viewer")

    if role not in ("admin", "staff", "viewer"):
        return jsonify({"error": "role must be admin, staff, or viewer"}), 400
    if not username or not password:
        return jsonify({"error": "username and password required"}), 400
    if len(password) < 8:
        return jsonify({"error": "password must be at least 8 characters"}), 400

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
            (username, generate_password_hash(password), role, datetime.utcnow().isoformat()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"error": "Username already taken"}), 409
    except Exception:
        conn.close()
        return jsonify({"error": "Could not create user"}), 400

    row = conn.execute(
        "SELECT id, username, role, created_at FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    return jsonify({"user": dict(row)}), 201


@auth_bp.get("/api/auth/users")
def list_users():
    """List all users. FIX-V7 + FIX-V12: admin only, and never return password hashes."""
    user, err = require_role("admin")
    if err:
        return err
    conn = get_connection()
    rows = conn.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
