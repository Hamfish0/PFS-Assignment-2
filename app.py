"""
nu-tracker-inventory-company pty - Flask entrypoint.

All historical vulnerabilities documented in SECURITY_ANALYSIS.md have been
remediated. See vulns_fixed.md for the full writeup. Inline fixes are tagged
`# FIX-Vn:`.
"""

import logging
import os

from flask import Flask, jsonify, send_from_directory
from werkzeug.exceptions import HTTPException

from database import init_db
from routes.auth import auth_bp, log_request
from routes.inventory import inventory_bp
from routes.locations import locations_bp
from routes.suppliers import suppliers_bp

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")


@app.after_request
def after_request(response):
    """FIX-V10: CORS wildcard headers removed.

    The SPA is served from the same origin as the API, so no
    Access-Control-Allow-* headers are required. Removing the
    `Access-Control-Allow-Origin: *` header prevents a malicious third-party
    site from invoking these endpoints with the user's bearer token (if one
    were ever placed in a place a cross-origin request could read).

    We keep the request log invocation so audit telemetry still works, but
    log_request() itself now redacts bearer tokens and password fields
    (FIX-V7).
    """
    log_request()
    return response


@app.errorhandler(Exception)
def handle_exception(exc):
    if isinstance(exc, HTTPException):
        return exc
    app.logger.exception("unhandled exception in request: %s", exc)
    return jsonify({"error": "Internal server error"}), 500


app.register_blueprint(auth_bp)
app.register_blueprint(inventory_bp)
app.register_blueprint(locations_bp)
app.register_blueprint(suppliers_bp)


@app.route("/")
def index():
    """Serve the single-page frontend."""
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:path>")
def static_proxy(path):
    """Serve any other static asset by path."""
    full = os.path.join(STATIC_DIR, path)
    if os.path.isfile(full):
        return send_from_directory(STATIC_DIR, path)
    return send_from_directory(STATIC_DIR, "index.html")


if __name__ == "__main__":
    init_db()

    # FIX-V11: debug mode is OFF by default. The Werkzeug interactive debugger
    # is a remote code execution vector if exposed, and `debug=True` also
    # leaks tracebacks to clients regardless of the V9 fix above.
    debug = os.environ.get("INVTRACKER_DEBUG", "").lower() in ("1", "true", "yes")

    # HTTPS is on by default using a self-signed adhoc certificate.
    # Set INVTRACKER_NO_TLS=1 only when TLS is terminated upstream
    # (e.g. nginx/Caddy reverse proxy with a real certificate).
    no_tls = os.environ.get("INVTRACKER_NO_TLS", "").lower() in ("1", "true", "yes")
    ssl_context = None if no_tls else "adhoc"

    logging.basicConfig(level=logging.INFO)
    scheme = "http" if no_tls else "https"
    print(f"[invtracker] Serving on {scheme}://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=debug, ssl_context=ssl_context)
