# nu-tracker — Progress Tracker

This document is a hand-off log for future AI agents (and humans) picking up
development of nu-tracker. Update the stage table below whenever you finish
or change scope. Keep it brief: this file is read first.

## Quick context

- Goal: A deliberately-vulnerable Flask + SQLite + vanilla-JS inventory app
  used for academic security analysis. **Twelve documented vulnerabilities**
  must remain intact and tagged in source as `# VULN-[ID]: [name]`.
- Authoritative spec: the original project prompt; the vulnerability spec
  lives in `SECURITY_ANALYSIS.md`.
- Entry point: `python app.py` → http://localhost:5000.
- Defaults: admin/admin123, staff/staff123, viewer/viewer123.

## Stages

| #  | Stage                                                      | Status     | Notes |
|----|------------------------------------------------------------|------------|-------|
| 1  | Project scaffold (dirs, requirements.txt)                  | DONE       | Flask 3.0.3, PyJWT 2.8.0 pinned. |
| 2  | Database schema + seed (`database.py`)                     | DONE       | 5 tables, 3 users, 3 suppliers, 4 locations, 10 items, 1 audit row. |
| 3  | Auth routes (`routes/auth.py`)                             | DONE       | Login / register / list-users. Implements V2, V3, V4, V7, V8. |
| 4  | Inventory routes (`routes/inventory.py`)                   | DONE       | List / search / get / create / update / delete / audit. Implements V1, V5, V6 (server side), V9, V12. |
| 5  | Locations + suppliers routes                               | DONE       | Read-only. Locations endpoint joins items per location. |
| 6  | Flask app entrypoint (`app.py`)                            | DONE       | Wires blueprints, CORS (V10), HTTP-only run (V11), verbose error handler (V9). |
| 7  | Frontend HTML (`static/index.html`)                        | DONE       | Login, register, navbar with token chip, 5 tabs, 2 modals. |
| 8  | Frontend styling (`static/style.css`)                      | DONE       | Dark industrial theme, green/amber accents, monospace. |
| 9  | Frontend logic (`static/app.js`)                           | DONE       | Auth, CRUD, search, detail/edit modals, all 5 tabs. innerHTML on stored fields (V6). |
| 10 | README.md                                                  | DONE       | Setup, run, demo steps per feature. |
| 11 | SECURITY_ANALYSIS.md                                       | DONE       | All 12 vulnerabilities documented with attack/impact/mitigation/OWASP. |
| 12 | Local smoke test (`python app.py`, hit endpoints)          | DONE       | Server boots, DB seeds, /, /api/inventory, /api/auth/login verified. |

## How to resume

1. Read this file, then `SECURITY_ANALYSIS.md` for the security contract.
2. Skim `app.py` for the blueprint wiring.
3. `pip install -r requirements.txt && python app.py` — confirm boot.
4. Open http://localhost:5000 and log in as `admin / admin123`.
5. Each intentional flaw is tagged `# VULN-[ID]: [name]` — preserve them
   unless the task is explicitly to remediate one.

## Open / future work (not in original scope, but reasonable next steps)

- Pagination on `/api/inventory` and `/api/audit` (currently returns up to 500 rows).
- A "remediated" branch that fixes each VULN, paired with regression tests.
- A pytest suite covering happy-path CRUD and one exploit per vulnerability.
- A small RFID-scan simulator endpoint (`POST /api/scan` with an RFID tag
  body) to emulate phone-side reads.
- Dockerfile + compose for one-command demos.

## Conventions / gotchas

- Backend uses parameterised SQL **except** in `search_items()` (V1 is intentional).
- Frontend uses `.innerHTML` on stored fields **on purpose** (V6 is intentional).
  Do not "helpfully" switch to `textContent` without coordinating.
- `data/inventory.db` is recreated only if absent. To re-seed, delete the file.
- `requests.log` is gitignore-worthy but is part of V7 — leave the write path alone.
- All routes assume the bearer token is in `Authorization: Bearer <jwt>`.
  Login response shape: `{ token, user: { id, username, role } }`.
