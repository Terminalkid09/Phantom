# Phantom Lab — managed phone (MDM + adbd + app sandbox)
# Authorized LOCAL testing only.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# cryptography backs Flask's `ssl_context="adhoc"`: 8443 must speak TLS.
RUN pip install --no-cache-dir "flask==3.0.3" "cryptography==43.0.3"

COPY device.py /srv/phone/device.py
WORKDIR /srv/phone

# 5555 adb (real protocol) · 8443 MDM / mobile web
EXPOSE 5555 8443
CMD ["python", "/srv/phone/device.py"]
