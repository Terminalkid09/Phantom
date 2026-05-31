# syntax=docker/dockerfile:1
FROM python:3.11-slim-bullseye

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Install system dependencies (security tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    sudo \
    nmap \
    sqlmap \
    dnsutils \
    whois \
    netcat \
    tshark \
    iputils-ping \
    traceroute \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Ensure data directories exist
RUN mkdir -p data/logs data/sessions data/presets

# Final setup
ENTRYPOINT ["python", "-m", "phantom.main"]
