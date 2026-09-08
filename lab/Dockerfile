# Phantom Lab — DMZ host (multi-stage, "hard")
# Authorized LOCAL testing only. Internet-exposed web app + SSH jump host.
#
# Chain a professional would have to walk:
#   web SQLi / SSRF  ->  backup creds (NOT in any wordlist)
#   ssh backup@dmz   ->  privesc via sudo rsync (GTFObins) -> root on DMZ
#   root reads pivot secrets ->  ssh dev@internal (lateral movement)
#   internal privesc (SUID)  ->  root on internal
#   beacon + persistence on the internal host
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        vsftpd \
        python3 \
        python3-flask \
        procps \
        curl \
        rsync \
        sudo \
        netcat-openbsd \
        lsof \
    && rm -rf /var/lib/apt/lists/*

# ── SSH: backup (strong password, NOT in wordlists) ──────────────────────
RUN mkdir /var/run/sshd \
    && (userdel backup 2>/dev/null || true); useradd -m -s /bin/bash backup \
    && echo 'backup:S3cureB4ckup!22' | chpasswd \
    && sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config \
    && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config \
    && echo 'UsePAM no' >> /etc/ssh/sshd_config

# ── Privesc: backup can sudo rsync as root (GTFObins) ────────────────────
RUN echo 'backup ALL=(ALL) NOPASSWD: /usr/bin/rsync' > /etc/sudoers.d/backup-rsync \
    && chmod 440 /etc/sudoers.d/backup-rsync

# ── Internal pivot secrets (read by backup -> lateral to internal host) ───
RUN mkdir -p /home/backup/.backup \
    && printf '%s\n' \
        'internal host: internal (172.28.0.20)' \
        'ssh: dev@internal, port 22' \
        'password: Piv0tMe!2024' \
        'dev can sudo (privesc to root on internal).' \
        > /home/backup/.backup/pivot.txt \
    && chown -R backup:backup /home/backup/.backup \
    && chmod 600 /home/backup/.backup/pivot.txt

# ── FTP anonymous (hint pointing at the web app) ─────────────────────────
RUN mkdir -p /srv/ftp/pub /var/run/vsftpd/empty \
    && printf 'PORT=YES\nlisten=YES\nanonymous_enable=YES\nlocal_enable=NO\nwrite_enable=YES\nanon_root=/srv/ftp\ndirmessage_enable=YES\nseccomp_sandbox=NO\nsecure_chroot_dir=/var/run/vsftpd/empty\n' > /etc/vsftpd.conf \
    && printf 'credentials are internal-only. get them from the intranet app /export. ssh /etc/passwd note: backup account.\n' > /srv/ftp/pub/note.txt \
    && printf 'Authorized testing only.\n' > /srv/ftp/pub/README.txt

# ── Web app (SQLi login, SSRF /export, upload path-traversal) ────────────
COPY webapp/ /srv/webapp/
RUN chmod +x /srv/webapp/app.py

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 2222 21 8081
ENTRYPOINT ["/entrypoint.sh"]