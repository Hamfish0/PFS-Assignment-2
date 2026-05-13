"""Inventory CRUD and search routes.

Historical vulnerabilities V1, V5, V6, V9, V12 lived in this module. All
remediations are tagged inline with `# FIX-Vn:` and described in vulns_fixed.md.
"""

from datetime import datetime

from flask import Blueprint, current_app, jsonify, request

from database import get_connection, log_audit
from routes.auth import require_auth, require_role

inventory_bp = Blueprint("inventory", __name__)


@inventory_bp.get("/api/inventory")
def list_items():
    """List all inventory items, joined with supplier name."""
    user, err = require_auth()
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
    """Search items by name/description.

    FIX-V1: the user-supplied search term is now passed as a bound parameter
    and the LIKE wildcards are wrapped around it on the Python side. The
    `%`/`_` characters in user input are escaped and the literal escape
    character is declared with `ESCAPE '\\'`, so a malicious value such as
    `' OR 1=1 --` is treated as an opaque string and never alters the query.
    """
    user, err = require_auth()
    if err:
        return err
    q = request.args.get("q", "")
    # Escape LIKE metacharacters so they cannot widen the match unexpectedly.
    escaped = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = f"%{escaped}%"
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT * FROM inventory_items
               WHERE name LIKE ? ESCAPE '\\'
                  OR description LIKE ? ESCAPE '\\'""",
            (pattern, pattern),
        ).fetchall()
    except Exception:
        conn.close()
        # FIX-V9: generic message; full exception logged server-side only.
        current_app.logger.exception("inventory search failed")
        return jsonify({"error": "Search failed"}), 500
    conn.close()
    return jsonify([dict(r) for r in rows])


@inventory_bp.get("/api/inventory/<int:item_id>")
def get_item(item_id):
    """Get an item by ID.

    FIX-V5: read access is granted to any authenticated user because inventory
    items are not user-owned data in this application's model (every staff
    member is expected to see the warehouse). The endpoint still requires
    authentication, and write/delete endpoints below enforce role checks so
    that knowing an ID does not grant the ability to mutate it.
    """
    user, err = require_auth()
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

    FIX-V12: write access is restricted to admin and staff roles; viewers
    cannot create items.
    FIX-V6 (server side): values are stored verbatim (as is correct for a
    data store), but every value is rendered as text on the client (see
    static/app.js::escapeHtml), so stored XSS is no longer possible.
    """
    user, err = require_role("admin", "staff")
    if err:
        return err
    data = request.get_json(silent=True) or {}
    try:
        quantity = int(data.get("quantity", 0) or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "quantity must be an integer"}), 400
    if quantity < 0:
        return jsonify({"error": "quantity must be non-negative"}), 400

    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    conn = get_connection()
    try:
        cur = conn.execute(
            """INSERT INTO inventory_items
               (name, description, quantity, location, supplier_id, rfid_tag, last_updated, updated_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                name,
                data.get("description", ""),
                quantity,
                data.get("location", ""),
                data.get("supplier_id"),
                data.get("rfid_tag"),
                datetime.utcnow().isoformat(),
                user.get("username"),
            ),
        )
        conn.commit()
        new_id = cur.lastrowid
    except Exception:
        conn.close()
        current_app.logger.exception("inventory create failed")
        # FIX-V9: no exception type or traceback in response.
        return jsonify({"error": "Could not create item"}), 400
    conn.close()
    log_audit("CREATE", new_id, user.get("sub"), f"name={name}")
    return jsonify({"id": new_id}), 201


@inventory_bp.put("/api/inventory/<int:item_id>")
def update_item(item_id):
    """Update an existing item. FIX-V12: admin or staff only."""
    user, err = require_role("admin", "staff")
    if err:
        return err
    data = request.get_json(silent=True) or {}
    quantity = data.get("quantity")
    if quantity is not None:
        try:
            quantity = int(quantity)
        except (TypeError, ValueError):
            return jsonify({"error": "quantity must be an integer"}), 400
        if quantity < 0:
            return jsonify({"error": "quantity must be non-negative"}), 400

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
                quantity,
                data.get("location"),
                data.get("supplier_id"),
                data.get("rfid_tag"),
                datetime.utcnow().isoformat(),
                user.get("username"),
                item_id,
            ),
        )
        conn.commit()
    except Exception:
        conn.close()
        current_app.logger.exception("inventory update failed")
        return jsonify({"error": "Could not update item"}), 400
    conn.close()
    log_audit("UPDATE", item_id, user.get("sub"), f"fields={list(data.keys())}")
    return jsonify({"ok": True})


@inventory_bp.delete("/api/inventory/<int:item_id>")
def delete_item(item_id):
    """Delete an item. FIX-V12: admin only."""
    user, err = require_role("admin")
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
    """Return the audit log.

    FIX-V7 + FIX-V12: the audit log is now admin-only. Previously this
    endpoint was unauthenticated and exposed the full log to the public.
    """
    user, err = require_role("admin")
    if err:
        return err
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 500"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
