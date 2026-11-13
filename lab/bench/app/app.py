"""The bench app: four deliberate defects and one dead end.

Nothing here is subtle on purpose — it is a TARGET, not a puzzle for humans.
What makes it non-trivial for the tool is the shape:

* the SQL injection is in a POST body, not a query string, so a scanner that
  only appends payloads to URLs will not see it;
* ``/api/users/<id>`` is only an IDOR once you HAVE a session, so it is
  invisible until the SQLi lands;
* ``/api/fetch`` is SSRF and reaches a service that is not published on the
  host at all (``admin:5001``), so the whole point is the chain;
* ``/download`` is path traversal, but the interesting file is a leftover
  backup with a password that the login does not need — a second dead end.

Deliberately NOT here: any real command execution. The Tomcat container is the
RCE path; this app is the chain that proves a foothold without one.
"""

import os
import sqlite3

import requests
from flask import Flask, jsonify, request, send_file

app = Flask(__name__)
DB = "/srv/app.db"

ADMIN_URL = os.environ.get("ADMIN_URL", "http://admin:5001")


def _db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def _init():
    conn = _db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT
        );
        INSERT OR IGNORE INTO users VALUES (1, 'operator', 'phantom-lab', 'user');
        INSERT OR IGNORE INTO users VALUES (2, 'admin', 'Adm1n-Lab-2026', 'admin');
        """)
    conn.commit()
    conn.close()


_init()


@app.route("/")
def index():
    return jsonify({"service": "portal", "version": "1.4.2",
                    "endpoints": ["/login", "/api/users/<id>", "/api/fetch",
                                  "/download"]})


@app.route("/login", methods=["POST"])
def login():
    """SQLi: the password is concatenated into the statement.

    ``username=admin&password=' OR '1'='1`` logs in as the first row, and a
    UNION-shaped payload can return another user's role. A scanner that only
    fuzzes GET parameters never touches this.
    """
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    query = (f"SELECT id, username, role FROM users "
             f"WHERE username = '{username}' AND password = '{password}'")
    try:
        row = _db().execute(query).fetchone()
    except sqlite3.Error as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    if not row:
        return jsonify({"ok": False}), 401
    return jsonify({"ok": True, "id": row["id"], "user": row["username"],
                    "role": row["role"]})


@app.route("/api/users/<int:user_id>")
def user(user_id):
    """IDOR: any authenticated caller reads any user, by id."""
    if not request.cookies.get("sid") and not request.headers.get("X-User"):
        return jsonify({"ok": False, "error": "auth required"}), 401
    row = _db().execute("SELECT id, username, role FROM users WHERE id = ?",
                        (user_id,)).fetchone()
    if not row:
        return jsonify({"ok": False}), 404
    return jsonify({"id": row["id"], "username": row["username"],
                    "role": row["role"]})


@app.route("/download")
def download():
    """Path traversal: the name is joined, not confined."""
    name = request.args.get("file", "readme.txt")
    path = os.path.join("/srv/files", name)
    try:
        return send_file(path)
    except Exception:
        return jsonify({"ok": False, "path": path}), 404


@app.route("/api/fetch")
def fetch():
    """SSRF: the app fetches whatever URL it is handed, from INSIDE the network.

    That is the only route to ``admin:5001``, which is not published on the
    host: the chain is SQLi (for a session) -> SSRF (for the admin token) ->
    flag.
    """
    url = request.args.get("url", "")
    if not url.lower().startswith(("http://", "https://")):
        return jsonify({"ok": False, "error": "url must be http(s)"}), 400
    try:
        resp = requests.get(url, timeout=4)
        return jsonify({"ok": True, "status": resp.status_code,
                        "body": resp.text[:2000]})
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)[:200]}), 502


@app.route("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
