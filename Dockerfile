# syntax=docker/dockerfile:1
FROM kalilinux/kali-rolling

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Install system dependencies (security tools + C++ build chain)
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core
    git \
    sudo \
    python3 \
    python3-pip \
    # Recon & Scanning
    nmap \
    dnsutils \
    whois \
    netcat-openbsd \
    tshark \
    iputils-ping \
    traceroute \
    # Web Testing
    gobuster \
    nikto \
    sqlmap \
    ffuf \
    # Brute Force
    hydra \
    medusa \
    john \
    hashcat \
    # WiFi
    aircrack-ng \
    reaver \
    hcxdumptool \
    hcxtools \
    # Exploit
    exploitdb \
    # C++ Beacon Build Chain
    g++ \
    mingw-w64 \
    cmake \
    make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# Copy the rest of the application
COPY . .

# Ensure data directories exist
RUN mkdir -p data/logs data/sessions data/presets

# Final setup
ENTRYPOINT ["python3", "-m", "phantom.main"]
