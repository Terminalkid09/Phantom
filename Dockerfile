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
      org.opencontainers.image.version="3.0.0" \
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
    nmap dnsutils whois netcat-openbsd tshark iputils-ping traceroute netdiscover arp-scan fping \
    # Web testing
    gobuster nikto sqlmap ffuf \
    # Brute force
    hydra medusa john hashcat \
    # WiFi
    aircrack-ng reaver hcxdumptool hcxtools \
    # OSINT
    sherlock exploitdb theharvester \
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
    ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android28-clang --version >/dev/null 2>&1

# ── Cross-compile OpenSSL for Android ──────────────────────────────────────
RUN NDK_HOME=${ANDROID_NDK_HOME} && \
    TOOLCHAIN=$NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64 && \
    export PATH=$TOOLCHAIN/bin:$PATH && \
    export ANDROID_NDK_ROOT=$NDK_HOME && \
    export CC=aarch64-linux-android28-clang && \
    export AR=llvm-ar && \
    export RANLIB=llvm-ranlib && \
    cd /tmp && \
    curl -sL https://github.com/openssl/openssl/releases/download/openssl-3.4.1/openssl-3.4.1.tar.gz -o openssl.tgz && \
    tar xzf openssl.tgz && \
    cd openssl-3.4.1 && \
    ./Configure android-arm64 no-shared no-asm -D__ANDROID_API__=28 --prefix=/tmp/openssl-install && \
    make -j$(nproc) && \
    make install_sw && \
    NDK_SYSROOT=$TOOLCHAIN/sysroot && \
    NDK_LIB=$NDK_SYSROOT/usr/lib/aarch64-linux-android && \
    cp libcrypto.a libssl.a $NDK_LIB/ && \
    cp -r include/openssl $NDK_SYSROOT/usr/include/openssl && \
    mkdir -p $NDK_SYSROOT/usr/include/aarch64-linux-android/openssl && \
    cp include/openssl/configuration.h include/openssl/opensslv.h $NDK_SYSROOT/usr/include/aarch64-linux-android/openssl/ && \
    sed -i 's/30600/30400/' $NDK_SYSROOT/usr/include/openssl/configuration.h && \
    sed -i 's/30600/30400/' $NDK_SYSROOT/usr/include/aarch64-linux-android/openssl/configuration.h && \
    rm -rf /tmp/openssl*

# ── osxcross (macOS cross-compiler skeleton) ─────────────────────────────────
RUN cd /opt && \
    git clone --depth=1 https://github.com/tpoechtrager/osxcross.git ${OSXCROSS_ROOT} && \
    mkdir -p ${OSXCROSS_ROOT}/SDK && \
    echo "osxcross SDK must be added manually (see osxcross docs)"

# ── Runtime secrets ─────────────────────────────────────────────────────────
# Do not pass C2 keys as Docker build args: ARG/ENV values can remain in image
# metadata and layers. docker-compose injects secrets at runtime via .env;
# compile_beacon then writes the matching generated config when explicitly run.
ENV PATH=${OSXCROSS_ROOT}/bin:${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

# ── Application setup ────────────────────────────────────────────────────────
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

COPY . .

RUN pip install --no-cache-dir --break-system-packages -e . \
 && pip install --no-cache-dir --break-system-packages pytest pytest-asyncio pytest-cov pytest-timeout

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

# Beacon crypto/C2 configuration is generated at runtime by `generate` or
# `compile_beacon`, after runtime secrets are injected. No secret is baked into
# this image during the build.

# ── Entry point ──────────────────────────────────────────────────────────────
# Keep the image ready for an interactive operator session; launch Phantom
# explicitly so Docker never starts a listener or Telegram bot implicitly.
CMD ["sleep", "infinity"]
