# nu-tracker

A deliberately-vulnerable inventory tracking application for
**nu-tracker-inventory-company pty**, simulating an RFID-based stock
management system used by a small startup. Users can view stock levels,
locate items, log inventory movements, and manage suppliers.

> **Warning** — This application is intentionally insecure for
> educational and security-analysis purposes. It contains twelve documented
> vulnerabilities (see `SECURITY_ANALYSIS.md`). **Do NOT deploy in production
> and do NOT expose it on a public network.**

## Stack

- Backend: Python 3.10+ / Flask / SQLite
- Frontend: Single-page vanilla HTML/CSS/JS
- Transport: Plain HTTP (no TLS — intentional)
- Auth: JWT (intentionally weak)

## Prerequisites

- Python 3.10 or newer
- `pip`

## Installation

```bash
pip install -r requirements.txt
```

## Running

```bash
python app.py
```

The server starts on `http://localhost:5000`. The SQLite database is
auto-created at `data/inventory.db` and seeded with demo data on first run.

## Default credentials

| Username | Password   | Role   |
|----------|------------|--------|
| admin    | admin123   | admin  |
| staff    | staff123   | staff  |
| viewer   | viewer123  | viewer |

Roles are stored but never enforced by the routes (see `V12` in
`SECURITY_ANALYSIS.md`).

## Demoing each feature

1. **Login** — open `http://localhost:5000`, log in as `admin / admin123`.
2. **Inventory table** — the landing tab shows all stock items with quantity
   badges (green / amber / red), RFID tags, and last-updated timestamps.
3. **Search** — type any term in the search bar. To demonstrate **SQL
   injection (V1)** try `' OR 1=1 --` which returns every row.
4. **Add item** — click `+ Add Item`. To demonstrate **stored XSS (V6)**,
   create an item with the name `<img src=x onerror=alert('XSS')>` and watch
   it fire when the list re-renders.
5. **Item detail** — click `view` on any row to open the modal with full
   details and audit history. Change the URL ID to demo **IDOR (V5)**.
6. **Locations tab** — text-based map of which items live at which physical
   location (Warehouse A, Office Floor 1, Server Room, Receiving Dock).
7. **Suppliers tab** — list of supplier contacts.
8. **Users tab** — lists every user including their **plaintext password
   (V3, V7)**. Note the warning banner.
9. **Audit tab** — full audit log with no authentication check on the
   endpoint (`GET /api/audit`).
10. **Token exposure** — the navbar displays the raw JWT, and it is also
    written to `requests.log` along with every request body.

## File layout

```
nu-tracker/
├── app.py                  Flask entrypoint
├── database.py             SQLite schema + seed
├── routes/
│   ├── auth.py             login/register/users
│   ├── inventory.py        CRUD + search
│   ├── locations.py        location listing
│   └── suppliers.py        supplier listing
├── static/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── data/inventory.db       auto-created
├── requirements.txt
├── README.md
├── SECURITY_ANALYSIS.md    full vulnerability writeup
└── progress_tracker.md     dev hand-off
```

## License / use

Academic use only.
