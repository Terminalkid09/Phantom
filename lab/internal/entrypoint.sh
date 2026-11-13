#!/bin/bash
set -e

/usr/sbin/sshd

echo "[internal] ssh(22) — reachable only by pivoting from the DMZ"
tail -f /dev/null