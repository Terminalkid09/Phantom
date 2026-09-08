"""
Hard-mode vulnerable "Corp Intranet" web app.

Attack surface (intentionally chained, NOT findable by port scan alone):
  1. /login         - UNION-based SQLi in the username field.
                      The users table holds the SSH + admin credentials.
  2. /export?url=   - SSRF: fetches file:// URLs (local file read) and
                      http://127.0.0.1:PORT (internal service pivot).
  3. /upload        - filename path traversal + webshell-style .py write,
                      combined with the static dir = RCE on the box.
The SSH account is NOT in any common wordlist — credentials only come
from dumping the database through the SQLi (or reading them via SSRF).

The app is a containerized demo for authorized testing only.
"""
import hashlib
import os
import sqlite3
import subprocess
import urllib.request

from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)
DB = "/opt/corp/intranet.db"
UPLOAD_DIR = "/opt/corp/uploads"


def db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn


def seed():
    os.makedirs("/opt/corp", exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = db()
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password_hash TEXT, role TEXT)"
    )
    # password for 'backup' is NOT in any wordlist — it must be dumped
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("admin", hashlib.md5(b"W1nt3r2024!x").hexdigest(), "administrator"),
    )
    conn.execute(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
        ("backup", hashlib.md5(b"S3cureB4ckup!22").hexdigest(), "service"),
    )
    conn.commit()
    conn.close()
    with open("/opt/corp/notes.txt", "w") as f:
        f.write(
            "internal: backup account used for nightly rsync over SSH.\n"
            "ssh port is non-standard (2222).\n"
        )
    # NOTE: backup's SSH password is deliberately NOT leaked through the app
    # anymore — the only way to get on the box is the upload RCE (or the
    # wordlist-brute, which fails: the password is not in any wordlist).


LOGIN_PAGE = """<html><body><h2>Corp Intranet Login</h2>
<form method="post"><input name="username" placeholder="user"><br>
<input name="password" type="password"><br><button>Login</button></form>
<p style="color:red">{{ err }}</p></body></html>"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(LOGIN_PAGE, err="")


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("username", "")
    pw = request.form.get("password", "")
    # INTENTIONAL: raw string interpolation -> UNION-based SQLi
    q = (
        "SELECT username, role FROM users WHERE username = '%s' "
        "AND password_hash = '%s'" % (user, hashlib.md5(pw.encode()).hexdigest())
    )
    try:
        conn = db()
        rows = conn.execute(q).fetchall()
        conn.close()
    except Exception as e:
        return render_template_string(LOGIN_PAGE, err=f"db error: {e}")
    if rows:
        row = rows[0]
        if row["role"] == "administrator":
            return redirect("/admin")
        return f"Welcome {row['username']} ({row['role']})"
    return render_template_string(LOGIN_PAGE, err="invalid credentials")


@app.route("/admin")
def admin():
    # the admin panel reads the whole users table — reachable via auth
    # bypass / SQLi ' or 1=1 --
    conn = db()
    rows = conn.execute("SELECT username, password_hash, role FROM users").fetchall()
    conn.close()
    out = "<html><body><h3>User table</h3><table border=1>"
    for r in rows:
        out += f"<tr><td>{r['username']}</td><td>{r['password_hash']}</td><td>{r['role']}</td></tr>"
    return out + "</table></body></html>"


@app.route("/export")
def export():
    """SSRF: fetch an arbitrary URL (file:// works) and show the content."""
    url = request.args.get("url", "")
    if not url:
        return "no url"
    try:
        with urllib.request.urlopen(url, timeout=4) as r:
            data = r.read(4096)
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        return f"fetch error: {e}"


@app.route("/upload", methods=["POST"])
def upload():
    """INTENTIONAL vulnerable upload: a real arbitrary-file-upload -> RCE.
    The server "processes" uploaded Python files by executing them (a
    classic report-generator feature) and returns their output — so an
    attacker who uploads a .py gets command execution on the box. This is
    the RCE a red teamer would use to skip credential hunting entirely.
    """
    f = request.files.get("file")
    if not f:
        return "no file"
    safe = os.path.basename((f.filename or "").replace("\\", "/"))
    if not safe:
        return "bad name"
    target = os.path.join(UPLOAD_DIR, safe)
    f.save(target)
    if safe.endswith(".py"):
        # INTENTIONAL: the "report generator" executes uploaded python
        try:
            out = subprocess.run(["python3", target], capture_output=True,
                                 text=True, timeout=10)
            return (out.stdout + out.stderr) or "(no output)"
        except Exception as e:
            return f"exec error: {e}"
    return f"uploaded to /uploads/{safe}"


@app.route("/uploads/<path:name>")
def serve_upload(name):
    p = os.path.join(UPLOAD_DIR, os.path.basename(name))
    if not os.path.exists(p):
        return "not found", 404
    with open(p, "rb") as fh:
        return fh.read()


@app.route("/health")
def health():
    return "ok"


if __name__ == "__main__":
    seed()
    app.run(host="0.0.0.0", port=8081, debug=False)
