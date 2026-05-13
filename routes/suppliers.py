"""Supplier routes."""

from flask import Blueprint, jsonify

from database import get_connection
from routes.auth import current_user

suppliers_bp = Blueprint("suppliers", __name__)


@suppliers_bp.get("/api/suppliers")
def list_suppliers():
    """Return all suppliers."""
    if not current_user():
        return jsonify({"error": "Authentication required"}), 401
    conn = get_connection()
    rows = conn.execute("SELECT * FROM suppliers ORDER BY name").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])
