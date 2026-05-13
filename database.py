"""
Database initialisation and helpers for nu-tracker-inventory-company pty.

NOTE: This module is part of a deliberately insecure application built for
academic security analysis. See SECURITY_ANALYSIS.md for the full list of
intentional vulnerabilities. Vulnerabilities are tagged inline with
`# VULN-[ID]: [name]`.
"""

import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "inventory.db")


def get_connection():
    """Return a new sqlite3 connection with row factory configured."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    # Allow foreign keys for cleaner relationship semantics.
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create tables and seed demo data if the DB is empty."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            -- VULN-V3: No Password Hashing - passwords are stored in plaintext.
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS suppliers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            contact_email TEXT,
            contact_phone TEXT,
            address TEXT
        );

        CREATE TABLE IF NOT EXISTS locations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            building TEXT,
            floor TEXT
        );

        CREATE TABLE IF NOT EXISTS inventory_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            quantity INTEGER NOT NULL DEFAULT 0,
            location TEXT,
            supplier_id INTEGER,
            rfid_tag TEXT UNIQUE,
            last_updated TEXT,
            updated_by TEXT,
            FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            item_id INTEGER,
            user_id INTEGER,
            timestamp TEXT NOT NULL,
            details TEXT
        );
        """
    )
    conn.commit()

    cur.execute("SELECT COUNT(*) AS c FROM users")
    if cur.fetchone()["c"] == 0:
        _seed(cur)
        conn.commit()

    conn.close()


def _seed(cur):
    """Insert demo users, suppliers, locations, items, and an initial audit row."""
    now = datetime.utcnow().isoformat()

    # VULN-V2: Hardcoded Credentials - admin / admin123 seeded into DB.
    # VULN-V3: No Password Hashing - plaintext passwords stored.
    users = [
        ("admin", "admin123", "admin"),
        ("staff", "staff123", "staff"),
        ("viewer", "viewer123", "viewer"),
    ]
    for u, p, r in users:
        cur.execute(
            "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
            (u, p, r, now),
        )

    suppliers = [
        ("Acme Hardware Co.", "sales@acme.example", "+61 2 5550 0100", "1 Acme Way, Sydney"),
        ("ByteWorks Distribution", "orders@byteworks.example", "+61 3 5550 0200", "42 Byte Ln, Melbourne"),
        ("Cable & Connectors Pty", "info@cnc.example", "+61 7 5550 0300", "9 Wire St, Brisbane"),
    ]
    cur.executemany(
        "INSERT INTO suppliers (name, contact_email, contact_phone, address) VALUES (?, ?, ?, ?)",
        suppliers,
    )

    locations = [
        ("Warehouse A", "Main bulk storage", "Bldg 1", "G"),
        ("Office Floor 1", "Staff workstation area", "Bldg 2", "1"),
        ("Server Room", "Climate-controlled rack room", "Bldg 1", "2"),
        ("Receiving Dock", "Inbound goods staging area", "Bldg 1", "G"),
    ]
    cur.executemany(
        "INSERT INTO locations (name, description, building, floor) VALUES (?, ?, ?, ?)",
        locations,
    )

    items = [
        ("Dell Latitude 7420 Laptop", "14-inch business laptop", 12, "Warehouse A", 2, "RFID-0001"),
        ("iPhone 15 Pro", "Company-issued smartphone", 6, "Office Floor 1", 2, "RFID-0002"),
        ("Dell U2723QE Monitor", "27-inch 4K USB-C monitor", 8, "Warehouse A", 1, "RFID-0003"),
        ("Cat6 Ethernet Cable 3m", "Blue patch cable", 120, "Server Room", 3, "RFID-0004"),
        ("USB-C Hub 7-port", "Docking hub with HDMI/Ethernet", 22, "Office Floor 1", 1, "RFID-0005"),
        ("HP LaserJet Pro Toner", "Black toner cartridge", 14, "Warehouse A", 1, "RFID-0006"),
        ("Logitech MX Master 3S", "Wireless productivity mouse", 30, "Office Floor 1", 2, "RFID-0007"),
        ("APC Smart-UPS 1500VA", "Rack-mount UPS", 4, "Server Room", 1, "RFID-0008"),
        ("Cisco Catalyst 9200 Switch", "24-port managed switch", 2, "Server Room", 1, "RFID-0009"),
        ("Pallet Jack", "Manual pallet jack, 2.5t", 3, "Receiving Dock", 3, "RFID-0010"),
    ]
    for name, desc, qty, loc, sup, rfid in items:
        cur.execute(
            """INSERT INTO inventory_items
               (name, description, quantity, location, supplier_id, rfid_tag, last_updated, updated_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (name, desc, qty, loc, sup, rfid, now, "admin"),
        )

    cur.execute(
        "INSERT INTO audit_log (action, item_id, user_id, timestamp, details) VALUES (?, ?, ?, ?, ?)",
        ("SEED", None, 1, now, "Initial demo data seeded"),
    )


def log_audit(action, item_id, user_id, details):
    """Insert an audit log entry. Used by routes for traceability."""
    conn = get_connection()
    conn.execute(
        "INSERT INTO audit_log (action, item_id, user_id, timestamp, details) VALUES (?, ?, ?, ?, ?)",
        (action, item_id, user_id, datetime.utcnow().isoformat(), details),
    )
    conn.commit()
    conn.close()
