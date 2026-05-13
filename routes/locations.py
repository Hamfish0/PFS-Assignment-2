"""Location routes."""

from flask import Blueprint, jsonify

from database import get_connection
from routes.auth import current_user

locations_bp = Blueprint("locations", __name__)


@locations_bp.get("/api/locations")
def list_locations():
    """List all known physical locations, plus the items currently at each."""
    if not current_user():
        return jsonify({"error": "Authentication required"}), 401
    conn = get_connection()
    locations = conn.execute("SELECT * FROM locations ORDER BY name").fetchall()
    items = conn.execute(
        "SELECT id, name, quantity, location, rfid_tag FROM inventory_items"
    ).fetchall()
    conn.close()
    result = []
    for loc in locations:
        loc_dict = dict(loc)
        loc_dict["items"] = [dict(i) for i in items if i["location"] == loc["name"]]
        result.append(loc_dict)
    return jsonify(result)
