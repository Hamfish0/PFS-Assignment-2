"""Authentication routes: login, register, list users."""

import base64
import json
import os
from datetime import datetime, timedelta

import jwt
from flask import Blueprint, jsonify, request

from database import get_connection, log_audit

auth_bp = Blueprint("auth", __name__)

# VULN-V2: Hardcoded Credentials - hardcoded admin password in source.
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"

# VULN-V4: Broken Authentication / Weak JWT - hardcoded weak secret.
JWT_SECRET = "secret"
JWT_ALGORITHM = "HS256"

REQUEST_LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "requests.log")


def _b64url_decode(data: str) -> bytes:
    """Decode a base64url string, padding as required."""
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def issue_token(user_row):
    """Issue a JWT for the given user row.

    VULN-V4: Broken Authentication / Weak JWT - we sign with a hardcoded weak
    secret and do not validate expiry on the verification path. The exp claim
    is included but `decode_token` does not enforce it.
    """
    payload = {
        "sub": user_row["id"],
        "username": user_row["username"],
        "role": user_row["role"],
        "exp": (datetime.utcnow() + timedelta(days=7)).timestamp(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str):
    """Decode a JWT.

    VULN-V4: Broken Authentication / Weak JWT
      - Accepts tokens with alg="none" by short-circuiting verification.
      - Disables expiry verification ({"verify_exp": False}).
    """
    if not token:
        return None
    try:
        header_b64 = token.split(".")[0]
        header = json.loads(_b64url_decode(header_b64))
        if header.get("alg", "").lower() == "none":
            payload_b64 = token.split(".")[1]
            return json.loads(_b64url_decode(payload_b64))
    except Exception:
        # Fall through to the signed path.
        pass

    return jwt.decode(
        token,
        JWT_SECRET,
        algorithms=[JWT_ALGORITHM],
        options={"verify_exp": False},
    )


def current_user():
    """Return the decoded JWT payload for the current request, or None."""
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip()
    if not token:
        return None
    try:
        return decode_token(token)
    except Exception:
        return None


def log_request():
    """Append a record of the request to a plaintext log file.

    VULN-V7: Sensitive Data Exposure - the Authorization header (including the
    raw bearer token) is written to a world-readable plaintext log file.
    """
    try:
        with open(REQUEST_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(
                f"{datetime.utcnow().isoformat()} {request.method} {request.path} "
                f"auth={request.headers.get('Authorization','')} "
                f"body={request.get_data(as_text=True)[:500]}\n"
            )
    except OSError:
        pass


@auth_bp.post("/api/auth/login")
def login():
    """Authenticate a user and return a JWT.

    VULN-V8: No Rate Limiting / Brute Force Protection - unlimited attempts.
    VULN-V3: No Password Hashing - plaintext comparison.
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_connection()
    # VULN-V1 also lives in inventory.search; here we use parameterised SQL
    # because the spec only mandates SQLi on the search endpoint.
    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()

    if not row or row["password"] != password:
        return jsonify({"error": "Invalid credentials"}), 401

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
    """Register a new user. No CAPTCHA, no email verification, no rate limit."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    role = data.get("role") or "viewer"

    if not username or not password:
        return jsonify({"error": "username and password required"}), 400

    conn = get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password, role, datetime.utcnow().isoformat()),
        )
        conn.commit()
    except Exception as exc:
        conn.close()
        # VULN-V9: Verbose Error Messages - full exception bubbled to the client.
        return jsonify({"error": str(exc), "type": exc.__class__.__name__}), 400

    row = conn.execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()
    conn.close()
    token = issue_token(row)
    return jsonify(
        {
            "token": token,
            "user": {"id": row["id"], "username": row["username"], "role": row["role"]},
        }
    )


@auth_bp.get("/api/auth/users")
def list_users():
    """List all users.

    VULN-V7: Sensitive Data Exposure - returns plaintext passwords.
    VULN-V12: Excessive Permissions / No RBAC - any authenticated user can call this.
    """
    # No role check on purpose (V12).
    conn = get_connection()
    rows = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
