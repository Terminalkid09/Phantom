"""IMDS mock — a minimal EC2 instance-metadata service for the cloud lab.

An SSRF or a command-injection on a cloud host almost always ends the same
way: the instance queries its metadata service and receives temporary
credentials. Without a metadata endpoint in the lab, that step of the chain
cannot be practised — every real cloud has one, so the lab has one too.

Served paths (the ones the real service answers on a v2-capable instance):

    PUT  /latest/api/token                      -> IMDSv2 session token
    GET  /latest/meta-data/iam/security-credentials/
                                                -> role name
    GET  /latest/meta-data/iam/security-credentials/<role>
                                                -> temporary credentials JSON
    GET  /latest/meta-data/instance-id
    GET  /latest/meta-data/local-ipv4
    GET  /latest/meta-data/placement/region
    GET  /latest/user-data

The credentials are FAKE and marked as such. Nothing here can authenticate
against a real provider; the point is that a client which blindly follows
the metadata endpoint learns a lesson it can only learn safely here.
"""

from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROLE_NAME = os.getenv("IMDS_ROLE", "phantom-lab-ec2-role")
REGION = os.getenv("IMDS_REGION", "eu-west-1")
INSTANCE_ID = os.getenv("IMDS_INSTANCE_ID", "i-0phantom0lab00001")
LOCAL_IPV4 = os.getenv("IMDS_LOCAL_IPV4", "172.31.0.20")

USER_DATA = """#!/bin/bash
# Lab user-data: a deliberately careless bootstrap.
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
aws s3 sync s3://phantom-lab-configs/ /etc/phantom-lab/ --quiet
"""


def credentials() -> dict:
    """Temporary credential blob, shaped exactly like the real response."""
    return {
        "Code": "Success",
        "LastUpdated": "2026-01-01T00:00:00Z",
        "Type": "AWS-HMAC",
        "AccessKeyId": "ASIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "IQoJb3JpZ2luX2VjEXAMPLEFAKEFAKEFAKE",
        "Expiration": "2030-01-01T00:00:00Z",
        "RoleName": ROLE_NAME,
        "_lab_note": "FAKE credentials — this is the Phantom cloud lab",
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "phantom-imds-mock"

    def log_message(self, fmt, *args):  # keep the container log readable
        return

    def _send(self, status: int, body: bytes, ctype: str = "text/plain"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except OSError:
            pass

    def do_PUT(self):  # noqa: N802
        if self.path.startswith("/latest/api/token"):
            token = "phantom-lab-imds-token"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
            self.send_header("Content-Length", str(len(token)))
            self.end_headers()
            self.wfile.write(token.encode())
            return
        self._send(404, b"not found")

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0].rstrip("/")
        if path in ("", "/latest", "/latest/meta-data",
                    "/latest/meta-data/iam", "/latest/meta-data/iam/security-credentials"):
            if path.endswith("security-credentials"):
                self._send(200, (ROLE_NAME + "\n").encode())
                return
            self._send(200, b"ok\n")
            return
        if path == f"/latest/meta-data/iam/security-credentials/{ROLE_NAME}":
            self._send(200, json.dumps(credentials()).encode(),
                       "application/json")
            return
        if path == "/latest/meta-data/instance-id":
            self._send(200, (INSTANCE_ID + "\n").encode())
            return
        if path == "/latest/meta-data/local-ipv4":
            self._send(200, (LOCAL_IPV4 + "\n").encode())
            return
        if path == "/latest/meta-data/placement/region":
            self._send(200, (REGION + "\n").encode())
            return
        if path == "/latest/user-data":
            self._send(200, USER_DATA.encode())
            return
        self._send(404, b"not found")


if __name__ == "__main__":
    port = int(os.getenv("IMDS_PORT", "1338"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
