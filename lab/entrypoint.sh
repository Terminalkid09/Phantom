#!/bin/bash
set -e

/usr/sbin/sshd
/usr/sbin/vsftpd /etc/vsftpd.conf &
python3 /srv/webapp/app.py &

echo "[dmz] ssh(2222) ftp(21) http(8081) — authorized local testing"
tail -f /dev/null