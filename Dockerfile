# syntax=docker/dockerfile:1
FROM kalilinux/kali-rolling

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Android NDK
ENV ANDROID_NDK_VERSION=r26c
ENV ANDROID_NDK_HOME=/opt/android-ndk
ENV ANDROID_NDK_CC=aarch64-linux-android28-clang++

# osxcross (macOS cross-compile)
ENV OSXCROSS_ROOT=/opt/osxcross
ENV PATH=${OSXCROSS_ROOT}/bin:${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH

# Set working directory
WORKDIR /app

# Install system dependencies (security tools + C++ build chain)
RUN echo "wireshark-common wireshark-common/install-setuid boolean true" | debconf-set-selections
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Essential for group management
    adduser \
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
    # OSINT & Exploit
    sherlock \
    exploitdb \
    # C++ Beacon Build Chain
    g++ \
    mingw-w64 \
    cmake \
    make \
    clang \
    llvm \
    pkg-config \
    libcurl4-openssl-dev \
    libssl-dev \
    default-jdk \
    android-tools-adb \
    wget \
    unzip \
    ca-certificates \
    libxml2-dev \
    libxslt1-dev \
    bison \
    flex \
    texinfo \
    help2man \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Android NDK
RUN mkdir -p /opt && \
    cd /tmp && \
    wget -q https://dl.google.com/android/repository/android-ndk-${ANDROID_NDK_VERSION}-linux.zip && \
    unzip -q android-ndk-${ANDROID_NDK_VERSION}-linux.zip && \
    mv android-ndk-${ANDROID_NDK_VERSION} ${ANDROID_NDK_HOME} && \
    rm android-ndk-${ANDROID_NDK_VERSION}-linux.zip && \
    echo "Android NDK installed at ${ANDROID_NDK_HOME}"

# Create symlink for libssl/libcrypto in NDK sysroot (fallback for static linking)
RUN mkdir -p ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib && \
    ln -sf /usr/lib/x86_64-linux-gnu/libssl.a ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/ 2>/dev/null || true && \
    ln -sf /usr/lib/x86_64-linux-gnu/libcrypto.a ${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib/ 2>/dev/null || true

# Install osxcross (macOS cross-compiler)
RUN cd /opt && \
    git clone https://github.com/tpoechtrager/osxcross.git ${OSXCROSS_ROOT} && \
    cd ${OSXCROSS_ROOT} && \
    git checkout master && \
    echo "osxcross cloned. SDK must be added manually or via build process." && \
    mkdir -p ${OSXCROSS_ROOT}/SDK

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

# Copy the rest of the application
COPY . .

# Install the package
RUN pip install --no-cache-dir --break-system-packages -e .

# Ensure data directories exist
RUN mkdir -p data/logs data/sessions data/presets data/beacons

# Final setup
ENTRYPOINT ["python3", "-m", "phantom.main"]
