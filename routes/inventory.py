"""Inventory CRUD and search routes."""

from datetime import datetime

from flask import Blueprint, jsonify, request

from database import get_connection, log_audit
from routes.auth import current_user

inventory_bp = Blueprint("inventory", __name__)


def _require_auth():
    """Return decoded user or a Flask response tuple if unauthenticated."""
    user = current_user()
    if not user:
        return None, (jsonify({"error": "Authentication required"}), 401)
    return user, None


@inventory_bp.get("/api/inventory")
def list_items():
    """List all inventory items, joined with supplier name."""
    user, err = _require_auth()
    if err:
        return err
    conn = get_connection()
    rows = conn.execute(
        """SELECT i.*, s.name AS supplier_name
           FROM inventory_items i
           LEFT JOIN suppliers s ON s.id = i.supplier_id
           ORDER BY i.id"""
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@inventory_bp.get("/api/inventory/search")
def search_items():
    """Search items by name.

    VULN-V1: SQL Injection - user input is concatenated into the SQL string
    via an f-string with no sanitisation or parameter binding. An attacker
    can supply `' OR 1=1 --` or stack additional clauses.
    """
    user, err = _require_auth()
    if err:
        return err
    q = request.args.get("q", "")
    conn = get_connection()
    try:
        # VULN-V1: SQL Injection - f-string with raw user input.
        sql = f"SELECT * FROM inventory_items WHERE name LIKE '%{q}%' OR description LIKE '%{q}%'"
        rows = conn.execute(sql).fetchall()
    except Exception as exc:
        conn.close()
        # VULN-V9: Verbose Error Messages.
        return jsonify({"error": str(exc), "sql": sql, "type": exc.__class__.__name__}), 500
    conn.close()
    return jsonify([dict(r) for r in rows])


@inventory_bp.get("/api/inventory/<int:item_id>")
def get_item(item_id):
    """Get an item by ID.

    VULN-V5: Insecure Direct Object Reference - any authenticated user can
    fetch any item by its sequential integer ID; there is no ownership or
    role check.
    """
    user, err = _require_auth()
    if err:
        return err
    conn = get_connection()
    row = conn.execute(
        """SELECT i.*, s.name AS supplier_name
           FROM inventory_items i
           LEFT JOIN suppliers s ON s.id = i.supplier_id
           WHERE i.id = ?""",
        (item_id,),
    ).fetchone()
    history = conn.execute(
        "SELECT * FROM audit_log WHERE item_id = ? ORDER BY id DESC LIMIT 20",
        (item_id,),
    ).fetchall()
    conn.close()
    if not row:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"item": dict(row), "history": [dict(r) for r in history]})


@inventory_bp.post("/api/inventory")
def create_item():
    """Create a new inventory item.

    VULN-V6: No Input Validation / XSS - name/description/location are stored
    verbatim, including any HTML/JS payload, and rendered with innerHTML in
    the frontend.
    """
    user, err = _require_auth()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO inventory_items
               (name, description, quantity, location, supplier_id, rfid_tag, last_updated, updated_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                data.get("name", ""),
                data.get("description", ""),
                int(data.get("quantity", 0) or 0),
                data.get("location", ""),
                data.get("supplier_id"),
                data.get("rfid_tag"),
                datetime.utcnow().isoformat(),
                user.get("username"),
            ),
        )
        conn.commit()
        new_id = cur.lastrowid
    except Exception as exc:
        conn.close()
        # VULN-V9: Verbose Error Messages.
        return jsonify({"error": str(exc), "type": exc.__class__.__name__}), 400
    conn.close()
    log_audit("CREATE", new_id, user.get("sub"), f"name={data.get('name','')}")
    return jsonify({"id": new_id}), 201


@inventory_bp.put("/api/inventory/<int:item_id>")
def update_item(item_id):
    """Update an existing item.

    VULN-V5: IDOR - no ownership check.
    VULN-V12: Excessive Permissions / No RBAC - any authenticated user can edit.
    """
    user, err = _require_auth()
    if err:
        return err
    data = request.get_json(silent=True) or {}
    conn = get_connection()
    try:
        conn.execute(
            """UPDATE inventory_items
               SET name = COALESCE(?, name),
                   description = COALESCE(?, description),
                   quantity = COALESCE(?, quantity),
                   location = COALESCE(?, location),
                   supplier_id = COALESCE(?, supplier_id),
                   rfid_tag = COALESCE(?, rfid_tag),
                   last_updated = ?,
                   updated_by = ?
               WHERE id = ?""",
            (
                data.get("name"),
                data.get("description"),
                data.get("quantity"),
                data.get("location"),
                data.get("supplier_id"),
                data.get("rfid_tag"),
                datetime.utcnow().isoformat(),
                user.get("username"),
                item_id,
            ),
        )
        conn.commit()
    except Exception as exc:
        conn.close()
        return jsonify({"error": str(exc), "type": exc.__class__.__name__}), 400
    conn.close()
    log_audit("UPDATE", item_id, user.get("sub"), f"fields={list(data.keys())}")
    return jsonify({"ok": True})


@inventory_bp.delete("/api/inventory/<int:item_id>")
def delete_item(item_id):
    """Delete an item.

    VULN-V12: Excessive Permissions / No RBAC - any authenticated user can
    delete any item; admin role is not enforced.
    VULN-V5: IDOR - sequential IDs with no ownership check.
    """
    user, err = _require_auth()
    if err:
        return err
    conn = get_connection()
    conn.execute("DELETE FROM inventory_items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()
    log_audit("DELETE", item_id, user.get("sub"), "deleted")
    return jsonify({"ok": True})


@inventory_bp.get("/api/audit")
def get_audit():
    """Return the full audit log.

    VULN-V7 / V12: No authentication or role check - public exposure of audit data.
    """
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 500"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
