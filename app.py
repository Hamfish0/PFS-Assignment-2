"""
nu-tracker-inventory-company pty - Flask entrypoint.

VULN-V11: Insecure HTTP (no TLS) - the development server runs on plain HTTP.
All traffic, including login credentials and JWTs, is transmitted in plaintext
and is trivially observable on any shared network.

Run with:  python app.py
"""

import os
import traceback

from flask import Flask, jsonify, send_from_directory

from database import init_db
from routes.auth import auth_bp, log_request
from routes.inventory import inventory_bp
from routes.locations import locations_bp
from routes.suppliers import suppliers_bp

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")


@app.after_request
def add_cors_and_log(response):
    """Attach permissive CORS headers and log each request.

    VULN-V10: CORS Misconfiguration - Access-Control-Allow-Origin: * with all
    methods and headers permitted from any origin.
    VULN-V7: Sensitive Data Exposure - logs include Authorization headers.
    """
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "*"
    log_request()
    return response


@app.errorhandler(Exception)
def handle_exception(exc):
    """Return full tracebacks to the client.

    VULN-V9: Verbose Error Messages - returns the full Python traceback so
    that internal paths, library versions, and SQL errors are exposed.
    """
    return (
        jsonify(
            {
                "error": str(exc),
                "type": exc.__class__.__name__,
                "traceback": traceback.format_exc(),
            }
        ),
        500,
    )


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
    # VULN-V11: Insecure HTTP - no TLS context, plain HTTP on 127.0.0.1:5000.
    # Debug=True also leaks the Werkzeug debugger PIN and tracebacks (V9).
    app.run(host="127.0.0.1", port=5000, debug=True)
