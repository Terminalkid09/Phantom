# syntax=docker/dockerfile:1
# =============================================================================
#  Phantom — Offensive Security Framework
#  Multi-stage Docker build for cross-platform C2 beacon compilation
# =============================================================================

# ── Stage 1: Cross-compilation toolchain ────────────────────────────────────
FROM kalilinux/kali-rolling AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /build

# Install cross-compilation dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # C++ build chain
    g++ gcc make cmake pkg-config \
    # MinGW (Windows cross-compiler)
    mingw-w64 \
    # Assembly & LLVM
    clang llvm binutils \
    # Libraries for Linux/macOS beacon
    libcurl4-openssl-dev libssl-dev \
    # Utilities
    wget ca-certificates unzip xz-utils \
    # Python
    python3 python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Stage 2: Final runtime image ────────────────────────────────────────────
FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="Phantom Framework" \
      org.opencontainers.image.description="Offensive Security CLI & C2 Framework" \
      org.opencontainers.image.version="2.0.0" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ANDROID_NDK_VERSION=r26c \
    ANDROID_NDK_HOME=/opt/android-ndk \
    OSXCROSS_ROOT=/opt/osxcross

# ── Install runtime tools ────────────────────────────────────────────────────
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections

RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core
    python3 python3-pip git sudo adduser \
    # Recon & Scan
    nmap dnsutils whois netcat-openbsd tshark iputils-ping traceroute \
    # Web testing
    gobuster nikto sqlmap ffuf \
    # Brute force
    hydra medusa john hashcat \
    # WiFi
    aircrack-ng reaver hcxdumptool hcxtools \
    # OSINT
    sherlock exploitdb \
    # C++ build chain (for beacon compilation inside container)
    g++ gcc make cmake pkg-config mingw-w64 clang llvm binutils \
    libcurl4-openssl-dev libssl-dev \
    # RCE deployer
    sshpass smbclient curl default-mysql-client postgresql-client \
    python3-impacket python3-psycopg2 \
    # Android
    android-tools-adb default-jdk \
    # Utilities
    wget unzip ca-certificates xz-utils bison flex texinfo help2man \
    libxml2-dev libxslt1-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# ── Android NDK ──────────────────────────────────────────────────────────────
RUN mkdir -p /opt && \
    cd /tmp && \
    wget -q https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip && \
    unzip -q android-ndk-${ANDROID_NDK_VERSION}-linux.zip && \
    mv android-ndk-${ANDROID_NDK_VERSION} ${ANDROID_NDK_HOME} && \
    rm android-ndk-${ANDROID_NDK_VERSION}-linux.zip && \
    ln -sf /usr/lib/aarch64-linux-gnu/libssl.so \
        ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libssl.so && \
    ln -sf /usr/lib/aarch64-linux-gnu/libcrypto.so \
        ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/aarch64-linux-android/libcrypto.so

# ── osxcross (macOS cross-compiler skeleton) ─────────────────────────────────
RUN cd /opt && \
    git clone --depth=1 https://github.com/tpoechtrager/osxcross.git ${OSXCROSS_ROOT} && \
    mkdir -p ${OSXCROSS_ROOT}/SDK && \
    echo "osxcross SDK must be added manually (see osxcross docs)"

# ── C2 keys (optional build-args, expected from .env or docker-compose) ─────
ARG PHANTOM_C2_KEY=
ARG PHANTOM_C2_IV=
ARG PHANTOM_PAYLOAD_TOKEN=
ENV PHANTOM_C2_KEY=${PHANTOM_C2_KEY} \
    PHANTOM_C2_IV=${PHANTOM_C2_IV} \
    PHANTOM_PAYLOAD_TOKEN=${PHANTOM_PAYLOAD_TOKEN} \
    PATH=${OSXCROSS_ROOT}/bin:${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

# ── Application setup ────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

RUN pip install --no-cache-dir --break-system-packages -e .

# ── Pre-build beacon assembly objects & reflective loader ────────────────────
RUN BEACON_SRC=phantom/payloads/beacon/src && \
    # PIC bootstrap & helpers
    for asm in syscalls pic_bootstrap peb_walker api_resolver stack_spoofer; do \
        x86_64-w64-mingw32-as --64 ${BEACON_SRC}/${asm}.asm -o ${BEACON_SRC}/${asm}.o; \
    done && \
    # Reflective loader bootstrap
    x86_64-w64-mingw32-as --64 ${BEACON_SRC}/reflective_loader_bootstrap.asm \
        -o ${BEACON_SRC}/reflective_loader_bootstrap.o && \
    # Reflective loader C core (PIC, no CRT)
    x86_64-w64-mingw32-gcc -c -O2 -fPIC -nostdlib -ffreestanding \
        -fno-stack-protector ${BEACON_SRC}/reflective_loader.c \
        -o ${BEACON_SRC}/reflective_loader.o

# ── Create runtime data directories ──────────────────────────────────────────
RUN mkdir -p data/logs data/sessions data/presets data/beacons data/cache data/downloads

# ── Generate default crypto config ───────────────────────────────────────────
RUN python3 -c "import sys; sys.path.insert(0,'.'); \
    from phantom.utils.c2_crypto import write_beacon_crypto_config; \
    write_beacon_crypto_config('phantom/payloads/beacon')"

# ── Entry point ──────────────────────────────────────────────────────────────
CMD ["sleep", "infinity"]
