#!/usr/bin/env python3
"""
nu-tracker API fuzzer.

Usage:
    python fuzzer.py                        # reads data/credentials.txt
    python fuzzer.py --url http://host:5000
    python fuzzer.py --admin-pass secret
"""

import argparse
import os
import sys

import requests

BASE = "https://localhost:5000"
TIMEOUT = 5

# ── colours ───────────────────────────────────────────────────────────────────
RED = "\033[91m"
YEL = "\033[93m"
GRN = "\033[92m"
CYN = "\033[96m"
DIM = "\033[2m"
BLD = "\033[1m"
RST = "\033[0m"

# ── payloads ──────────────────────────────────────────────────────────────────
SQL = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "'; DROP TABLE users; --",
    "' UNION SELECT 1,2,3 --",
    "1; SELECT * FROM users --",
    "admin'--",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1",
]

XSS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "<svg onload=alert(1)>",
]

SSTI = ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"]

BOUNDARY_STRINGS = [
    "",
    " ",
    "\t\n\r",
    "\x00",
    "\x00" * 10,
    "a" * 256,
    "a" * 10000,
    "../../../etc/passwd",
    "..\\..\\..\\windows\\system32",
    "null",
    "undefined",
    "true",
    "false",
]

BAD_INTEGERS = [-1, -999999, 2**31, 2**63, "abc", "", None, [], {}, 1.5, "1; DROP TABLE items"]

BAD_BODIES = [
    (b"",          "empty"),
    (b"not json",  "invalid JSON"),
    (b"[]",        "array"),
    (b"0",         "integer"),
    (b'"string"',  "bare string"),
    (b"null",      "null"),
]

ALL_STRINGS = SQL + XSS + SSTI + BOUNDARY_STRINGS

# ── results ───────────────────────────────────────────────────────────────────
findings: list[tuple] = []


def record(level, method, path, code, desc="", note=""):
    findings.append((level, method, path, code, desc, note))
    colour = RED if level == "CRASH" else YEL if level == "WARN" else DIM
    tag = f"{colour}[{level:5}]{RST}"
    d = f" ← {desc}" if desc else ""
    n = f"  {DIM}{note}{RST}" if note else ""
    print(f"  {tag} {method} {path} → {BLD}{code}{RST}{d}{n}")


# ── HTTP ──────────────────────────────────────────────────────────────────────
_s = requests.Session()
_s.max_redirects = 0
_s.verify = False  # self-signed adhoc cert
requests.packages.urllib3.disable_warnings()  # suppress InsecureRequestWarning


def _url(path):
    return BASE.rstrip("/") + path


def _headers(token):
    return {"Authorization": f"Bearer {token}"} if token else {}


def get(path, token=None):
    return _s.get(_url(path), headers=_headers(token), timeout=TIMEOUT)


def post(path, body=None, token=None, raw=None):
    h = {**_headers(token), "Content-Type": "application/json"}
    if raw is not None:
        return _s.post(_url(path), data=raw, headers=h, timeout=TIMEOUT)
    return _s.post(_url(path), json=body, headers=h, timeout=TIMEOUT)


def put(path, body, token=None):
    h = {**_headers(token), "Content-Type": "application/json"}
    return _s.put(_url(path), json=body, headers=h, timeout=TIMEOUT)


def delete(path, token=None):
    return _s.delete(_url(path), headers=_headers(token), timeout=TIMEOUT)


def verb(method, path, token=None, body=None):
    h = {**_headers(token), "Content-Type": "application/json"}
    return _s.request(method, _url(path), json=body, headers=h, timeout=TIMEOUT)


# ── helpers ───────────────────────────────────────────────────────────────────
def section(title):
    print(f"\n{BLD}{CYN}── {title} {'─' * max(0, 54 - len(title))}{RST}")


def chk(r, method, path, desc=""):
    code = r.status_code
    if code >= 500:
        record("CRASH", method, path, code, desc)
    else:
        record("OK   ", method, path, code, desc)


def expect_deny(r, method, path, desc="", msg="expected 401/403"):
    code = r.status_code
    if code not in (401, 403):
        record("WARN", method, path, code, desc, msg)
    else:
        record("OK   ", method, path, code, desc)


def login(username, password):
    try:
        r = post("/api/auth/login", {"username": username, "password": password})
        if r.status_code == 200:
            return r.json().get("token")
    except Exception:
        pass
    return None


def read_credentials():
    path = os.path.join(os.path.dirname(__file__), "data", "credentials.txt")
    out = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                if ":" in line:
                    u, _, p = line.strip().partition(":")
                    out[u.strip()] = p.strip()
    return out


# ══════════════════════════════════════════════════════════════════════════════
# TEST SUITES
# ══════════════════════════════════════════════════════════════════════════════

def suite_login():
    section("POST /api/auth/login — credential fuzzing")
    for u, p, label in [
        ("admin",  "",          "empty password"),
        ("",       "password",  "empty username"),
        ("",       "",          "both empty"),
        ("nobody", "password",  "unknown user"),
    ]:
        r = post("/api/auth/login", {"username": u, "password": p})
        expect_deny(r, "POST", "/api/auth/login", label, "expected 401")

    for inj in SQL:
        r = post("/api/auth/login", {"username": inj, "password": "x"})
        if r.status_code == 200:
            record("WARN", "POST", "/api/auth/login", r.status_code,
                   f"sql username={inj!r:.40}", "logged in with injection!")
        else:
            chk(r, "POST", "/api/auth/login", f"sql username={inj!r:.40}")

    for raw, desc in BAD_BODIES:
        r = post("/api/auth/login", raw=raw)
        chk(r, "POST", "/api/auth/login", f"malformed body: {desc}")

    section("POST /api/auth/login — rate limiting (7 attempts)")
    for i in range(7):
        r = post("/api/auth/login", {"username": "_ratelimit_", "password": "wrong"})
        if i >= 5 and r.status_code != 429:
            record("WARN", "POST", "/api/auth/login", r.status_code,
                   f"attempt {i + 1}", "expected 429 after 5 failures")
        else:
            record("OK   ", "POST", "/api/auth/login", r.status_code, f"attempt {i + 1}")


def suite_unauth(protected):
    section("Unauthenticated access to protected endpoints")
    for method, path in protected:
        r = verb(method, path, body={})
        expect_deny(r, method, path, "no token")


def suite_bad_tokens():
    section("Invalid / tampered tokens")
    bad = [
        ("empty",        ""),
        ("whitespace",   "   "),
        ("not-a-jwt",    "notajwt"),
        ("alg=none",     "eyJhbGciOiJub25lIn0.eyJzdWIiOjEsInJvbGUiOiJhZG1pbiJ9."),
        ("truncated",    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjF9"),
        ("null-byte",    "eyJ\x00hbGciOiJIUzI1NiJ9.x.x"),
        ("role=admin",   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
                         ".eyJzdWIiOjk5LCJ1c2VybmFtZSI6ImZha2UiLCJyb2xlIjoiYWRtaW4ifQ"
                         ".invalidsignature"),
    ]
    for desc, tok in bad:
        r = get("/api/inventory", token=tok)
        expect_deny(r, "GET", "/api/inventory", desc)


def suite_inventory(admin, staff, viewer):
    section("GET /api/inventory")
    for label, tok in [("admin", admin), ("staff", staff), ("viewer", viewer)]:
        chk(get("/api/inventory", token=tok), "GET", "/api/inventory", f"as {label}")

    section("GET /api/inventory/search — SQL injection")
    for inj in SQL:
        r = get(f"/api/inventory/search?q={requests.utils.quote(inj)}", token=admin)
        chk(r, "GET", "/api/inventory/search", f"sql={inj!r:.40}")

    section("GET /api/inventory/search — boundary values")
    for val in BOUNDARY_STRINGS:
        r = get(f"/api/inventory/search?q={requests.utils.quote(val)}", token=admin)
        chk(r, "GET", "/api/inventory/search", f"q={val!r:.40}")

    section("GET /api/inventory/<id> — boundary IDs")
    for item_id in [0, -1, 999999, 2**31]:
        r = get(f"/api/inventory/{item_id}", token=admin)
        chk(r, "GET", f"/api/inventory/{item_id}", f"id={item_id}")

    section("POST /api/inventory — viewer forbidden")
    expect_deny(
        post("/api/inventory", {"name": "x", "quantity": 1}, token=viewer),
        "POST", "/api/inventory", "viewer", "expected 403",
    )

    section("POST /api/inventory — fuzz name field")
    created = []
    for val in ALL_STRINGS:
        r = post("/api/inventory", {"name": val, "quantity": 1}, token=admin)
        if r.status_code >= 500:
            record("CRASH", "POST", "/api/inventory", r.status_code, f"name={val!r:.40}")
        elif r.status_code == 201:
            try:
                created.append(r.json()["id"])
            except Exception:
                pass
    for iid in created:
        try:
            delete(f"/api/inventory/{iid}", token=admin)
        except Exception:
            pass

    section("POST /api/inventory — fuzz quantity field")
    for val in BAD_INTEGERS:
        r = post("/api/inventory", {"name": "fuzz_qty", "quantity": val}, token=admin)
        if r.status_code >= 500:
            record("CRASH", "POST", "/api/inventory", r.status_code, f"quantity={val!r}")
        elif r.status_code == 201:
            try:
                delete(f"/api/inventory/{r.json()['id']}", token=admin)
            except Exception:
                pass

    section("POST /api/inventory — malformed bodies")
    for raw, desc in BAD_BODIES:
        r = post("/api/inventory", raw=raw, token=admin)
        chk(r, "POST", "/api/inventory", f"malformed: {desc}")

    section("PUT /api/inventory/<id> — fuzz fields")
    scratch = post("/api/inventory", {"name": "_fuzz_scratch_", "quantity": 0}, token=admin)
    sid = scratch.json().get("id") if scratch.status_code == 201 else 1

    for val in SQL + XSS:
        r = put(f"/api/inventory/{sid}", {"name": val}, token=admin)
        if r.status_code >= 500:
            record("CRASH", "PUT", f"/api/inventory/{sid}", r.status_code, f"name={val!r:.40}")

    for val in BAD_INTEGERS:
        r = put(f"/api/inventory/{sid}", {"quantity": val}, token=admin)
        if r.status_code >= 500:
            record("CRASH", "PUT", f"/api/inventory/{sid}", r.status_code, f"quantity={val!r}")

    if scratch.status_code == 201:
        delete(f"/api/inventory/{sid}", token=admin)

    section("DELETE /api/inventory/<id> — viewer forbidden")
    expect_deny(
        delete("/api/inventory/1", token=viewer),
        "DELETE", "/api/inventory/1", "viewer", "expected 403",
    )


def suite_users(admin, viewer):
    section("GET /api/auth/users — viewer forbidden")
    expect_deny(get("/api/auth/users", token=viewer), "GET", "/api/auth/users", "viewer")

    section("POST /api/auth/register — unauthenticated forbidden")
    expect_deny(
        post("/api/auth/register", {"username": "attacker", "password": "password1"}),
        "POST", "/api/auth/register", "no auth",
        "unauthenticated registration should be 401",
    )

    section("POST /api/auth/register — viewer forbidden")
    expect_deny(
        post("/api/auth/register", {"username": "attacker", "password": "password1"}, token=viewer),
        "POST", "/api/auth/register", "viewer",
    )

    section("POST /api/auth/register — invalid roles")
    for role in ["superadmin", "root", "", None, 1, [], {}]:
        r = post("/api/auth/register",
                 {"username": "_roletest_", "password": "password1", "role": role},
                 token=admin)
        if r.status_code == 201:
            record("WARN", "POST", "/api/auth/register", r.status_code,
                   f"role={role!r}", "invalid role accepted")
            try:
                uid = r.json()["user"]["id"]
                delete(f"/api/auth/users/{uid}", token=admin)
            except Exception:
                pass
        elif r.status_code >= 500:
            record("CRASH", "POST", "/api/auth/register", r.status_code, f"role={role!r}")
        else:
            record("OK   ", "POST", "/api/auth/register", r.status_code, f"role={role!r} (rejected)")

    section("POST /api/auth/register — fuzz username")
    for val in SQL + BOUNDARY_STRINGS[:6]:
        r = post("/api/auth/register",
                 {"username": val, "password": "password1", "role": "viewer"},
                 token=admin)
        if r.status_code >= 500:
            record("CRASH", "POST", "/api/auth/register", r.status_code, f"username={val!r:.40}")
        elif r.status_code == 201:
            try:
                delete(f"/api/auth/users/{r.json()['user']['id']}", token=admin)
            except Exception:
                pass

    section("DELETE /api/auth/users — self-delete blocked")
    users_r = get("/api/auth/users", token=admin)
    if users_r.status_code == 200:
        admin_id = next((u["id"] for u in users_r.json() if u["username"] == "admin"), None)
        if admin_id:
            r = delete(f"/api/auth/users/{admin_id}", token=admin)
            if r.status_code != 400:
                record("WARN", "DELETE", f"/api/auth/users/{admin_id}", r.status_code,
                       "self-delete", "expected 400")
            else:
                record("OK   ", "DELETE", f"/api/auth/users/{admin_id}", r.status_code,
                       "self-delete (blocked)")

    section("DELETE /api/auth/users — viewer forbidden")
    expect_deny(delete("/api/auth/users/999", token=viewer), "DELETE", "/api/auth/users/999", "viewer")

    section("DELETE /api/auth/users — boundary IDs")
    for bad_id in [0, -1, 999999, 2**31]:
        r = delete(f"/api/auth/users/{bad_id}", token=admin)
        chk(r, "DELETE", f"/api/auth/users/{bad_id}", f"id={bad_id}")


def suite_misc(admin):
    section("GET /api/audit — admin only")
    chk(get("/api/audit", token=admin), "GET", "/api/audit", "admin")

    section("GET /api/locations + /api/suppliers")
    for path in ["/api/locations", "/api/suppliers"]:
        chk(get(path, token=admin), "GET", path, "admin")

    section("HTTP verb tampering")
    for method, path in [
        ("DELETE", "/api/inventory"),
        ("PUT",    "/api/inventory"),
        ("GET",    "/api/auth/login"),
        ("DELETE", "/api/auth/users"),
        ("PATCH",  "/api/inventory/1"),
    ]:
        r = verb(method, path, token=admin, body={})
        if r.status_code >= 500:
            record("CRASH", method, path, r.status_code, "verb tamper")
        else:
            record("OK   ", method, path, r.status_code, "verb tamper")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global BASE

    p = argparse.ArgumentParser(description="nu-tracker API fuzzer")
    p.add_argument("--url",         default="http://localhost:5000")
    p.add_argument("--admin-pass",  help="Admin password (overrides credentials.txt)")
    p.add_argument("--staff-pass",  help="Staff password (overrides credentials.txt)")
    p.add_argument("--viewer-pass", help="Viewer password (overrides credentials.txt)")
    args = p.parse_args()
    BASE = args.url.rstrip("/")

    print(f"\n{BLD}nu-tracker fuzzer{RST}  →  {BASE}")

    creds       = read_credentials()
    admin_pass  = args.admin_pass  or creds.get("admin")
    staff_pass  = args.staff_pass  or creds.get("staff")
    viewer_pass = args.viewer_pass or creds.get("viewer")

    if not admin_pass:
        print(f"{RED}ERROR: admin password not found. "
              f"Pass --admin-pass or ensure data/credentials.txt exists.{RST}")
        sys.exit(1)

    print(f"{DIM}authenticating...{RST}")
    admin_token  = login("admin",  admin_pass)
    staff_token  = login("staff",  staff_pass)  if staff_pass  else None
    viewer_token = login("viewer", viewer_pass) if viewer_pass else None

    if not admin_token:
        print(f"{RED}ERROR: could not log in as admin — is the server running at {BASE}?{RST}")
        sys.exit(1)

    n = sum(1 for t in [admin_token, staff_token, viewer_token] if t)
    print(f"{GRN}authenticated — {n}/3 tokens obtained{RST}")

    # Fall back to admin token when staff/viewer aren't available so tests
    # that check role enforcement still run (they'll just produce WARNs if
    # the server incorrectly allows admin where it shouldn't).
    staff  = staff_token  or admin_token
    viewer = viewer_token or admin_token

    protected = [
        ("GET",    "/api/inventory"),
        ("GET",    "/api/locations"),
        ("GET",    "/api/suppliers"),
        ("GET",    "/api/auth/users"),
        ("GET",    "/api/audit"),
        ("POST",   "/api/inventory"),
        ("DELETE", "/api/inventory/1"),
    ]

    suite_login()
    suite_unauth(protected)
    suite_bad_tokens()
    suite_inventory(admin_token, staff, viewer)
    suite_users(admin_token, viewer)
    suite_misc(admin_token)

    # ── summary ───────────────────────────────────────────────────────────────
    crashes = [f for f in findings if f[0] == "CRASH"]
    warns   = [f for f in findings if f[0] == "WARN"]
    oks     = [f for f in findings if f[0] == "OK   "]

    print(f"\n{BLD}{'═' * 60}{RST}")
    print(f"{BLD}  SUMMARY{RST}   {len(findings)} checks  |  "
          f"{RED}{BLD}{len(crashes)} crash{'es' if len(crashes) != 1 else ''}{RST}  "
          f"{YEL}{BLD}{len(warns)} warning{'s' if len(warns) != 1 else ''}{RST}  "
          f"{GRN}{len(oks)} ok{RST}")
    print(f"{BLD}{'═' * 60}{RST}")

    if crashes:
        print(f"\n{RED}{BLD}CRASHES:{RST}")
        for _, method, path, code, payload, note in crashes:
            print(f"  {RED}{method} {path} → {code}{RST}  {payload}  {note}")

    if warns:
        print(f"\n{YEL}{BLD}WARNINGS:{RST}")
        for _, method, path, code, payload, note in warns:
            print(f"  {YEL}{method} {path} → {code}{RST}  {payload}  {note}")

    print()
    sys.exit(1 if crashes else 0)


if __name__ == "__main__":
    main()
