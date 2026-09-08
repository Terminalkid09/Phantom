# Phantom Lab — INTERNAL host (reachable only by pivoting from the DMZ).
# Authorized LOCAL testing only.
#
#   ssh dev@internal (creds come from DMZ pivot secrets)
#   vertical movement: SUID binary /usr/local/bin/roothelper -> root
#   /root/flag.txt is the final proof of full compromise.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        sudo \
        gcc \
        libc-dev \
        procps \
        curl \
        netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

# ── SSH: dev (strong password — comes from the DMZ pivot secrets) ────────
RUN mkdir /var/run/sshd \
    && useradd -m -s /bin/bash dev \
    && echo 'dev:Piv0tMe!2024' | chpasswd \
    && sed -i 's/^#Port 22/Port 22/' /etc/ssh/sshd_config \
    && echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config \
    && echo 'UsePAM no' >> /etc/ssh/sshd_config

# ── Vertical movement: SUID roothelper (classic setuid privesc) ──────────
RUN printf '%s\n' \
    '#include <stdlib.h>' \
    '#include <unistd.h>' \
    'int main(){ setuid(0); setgid(0); system("/bin/bash -p"); return 0; }' \
    > /tmp/roothelper.c \
    && gcc -o /tmp/roothelper /tmp/roothelper.c \
    && cp /tmp/roothelper /usr/local/bin/roothelper \
    && chown root:root /usr/local/bin/roothelper \
    && chmod u+s /usr/local/bin/roothelper \
    && rm -f /tmp/roothelper /tmp/roothelper.c \
    && printf '%s\n' \
        'the SUID binary /usr/local/bin/roothelper gives a root shell (find / -perm -4000 2>/dev/null).' \
        > /home/dev/hint.txt && chown dev:dev /home/dev/hint.txt

# ── proof of full compromise ──────────────────────────────────────────────
RUN mkdir -p /root && printf '%s\n' \
    'PHANTOM{internal_root_compr0mised_8912}' \
    > /root/flag.txt && chmod 400 /root/flag.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]