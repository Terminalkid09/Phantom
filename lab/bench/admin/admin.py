"""The internal service: no published port, so SSRF is the only way in.

It answers on the compose network as ``admin:5001`` and nothing on the host
maps to it. Reaching it from the operator box requires the app to fetch for
you, which is the whole reason the chain has a middle step.

The token check is real (a wrong token is a 403): the flag is not in a comment,
it is behind a two-step handshake that only a working SSRF can perform.
"""

import os

from flask import Flask, jsonify, request

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "PHANTOM{chain_complete_ssrf_to_admin}")
# Lab default, overridable by env so the secret is not a repository constant.
TOKEN = os.environ.get("ADMIN_TOKEN", "adm-7f3c91e2")


@app.route("/")
def index():
    return jsonify({"service": "admin", "token_endpoint": "/token"})


@app.route("/token")
def token():
    # Only the app's requests carry the internal header; a direct hit from
    # outside the compose network has no such header (and no route).
    if request.headers.get("X-Forwarded-For", "").count(",") > 3:
        return jsonify({"ok": False}), 429
    return jsonify({"ok": True, "token": TOKEN})


@app.route("/flag")
def flag():
    if request.args.get("token") != TOKEN:
        return jsonify({"ok": False, "error": "bad token"}), 403
    return jsonify({"ok": True, "flag": FLAG})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
