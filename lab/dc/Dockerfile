# Phantom Lab — Active Directory Domain Controller (Samba AD DC).
# Authorized LOCAL testing only. Provides a REAL domain (CORP.LOCAL) with
# Kerberos/LDAP so the AD chain (ad_enum -> kerberoast/as_rep -> dc_sync)
# can be exercised for real — with or without a beacon.
FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        samba \
        samba-ad-provision \
        samba-dsdb-modules \
        samba-vfs-modules \
        winbind \
        krb5-user \
        krb5-config \
        procps \
        iproute2 \
        dnsutils \
        ldap-utils \
        ldb-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/lib/samba /etc/samba/smb.conf

# provision the domain on first boot (entrypoint), expose standard AD ports
EXPOSE 53/udp 53/tcp 88/udp 88/tcp 135/tcp 139/tcp 389/tcp 445/tcp 464/udp 464/tcp 636/tcp 3268/tcp 3269/tcp

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]