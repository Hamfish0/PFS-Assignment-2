# nu-tracker

An inventory tracking application for **nu-tracker-inventory-company pty**,
simulating an RFID-based stock management system. Users can view stock levels,
locate items, log inventory movements, and manage suppliers.

## Stack

- Backend: Python 3.10+ / Flask / SQLite
- Frontend: Single-page vanilla HTML/CSS/JS
- Auth: JWT (HS256, 8-hour expiry)

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

The server starts on `https://localhost:5000` using a self-signed certificate.
Your browser will show a certificate warning — accept it to proceed.
The SQLite database is auto-created at `data/inventory.db` on first run.

## Credentials

Account passwords are randomly generated on first run and printed to the
console. They are also saved to `data/credentials.txt` and printed each time
the app starts.

To set fixed passwords instead, export environment variables before starting:

```bash
export INVTRACKER_ADMIN_PASSWORD=yourpassword
export INVTRACKER_STAFF_PASSWORD=yourpassword
export INVTRACKER_VIEWER_PASSWORD=yourpassword
python app.py
```

| Username | Role   |
|----------|--------|
| admin    | admin  |
| staff    | staff  |
| viewer   | viewer |

## Roles

| Role   | Capabilities                              |
|--------|-------------------------------------------|
| admin  | Full access including users and audit log |
| staff  | Read/write inventory, locations, suppliers |
| viewer | Read-only                                 |

## Features

1. **Inventory table** — all stock items with quantity badges, RFID tags, and
   last-updated timestamps.
2. **Search** — filter items by name or description.
3. **Add / edit items** — create and update inventory records with location,
   supplier, quantity, and RFID tag.
4. **Locations tab** — map of which items live at which physical location
   (Warehouse A, Office Floor 1, Server Room, Receiving Dock).
5. **Suppliers tab** — list of supplier contacts.
6. **Users tab** — admin-only list of accounts (no passwords exposed).
7. **Audit tab** — admin-only full audit log of all inventory changes.

## TLS

HTTPS is on by default using a self-signed certificate (no configuration needed).

For production, terminate TLS in a reverse proxy (nginx, Caddy, etc.) with a
real certificate and disable the built-in TLS:

```bash
INVTRACKER_NO_TLS=1 python app.py
```

## File layout

```
nu-tracker/
├── app.py                  Flask entrypoint
├── database.py             SQLite schema + seed
├── routes/
│   ├── auth.py             login / register / users
│   ├── inventory.py        CRUD + search
│   ├── locations.py        location listing
│   └── suppliers.py        supplier listing
├── static/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── data/
│   ├── inventory.db        auto-created on first run
│   └── credentials.txt     plaintext passwords (auto-created on first run)
└── requirements.txt
```

## License / use

Academic use only.
