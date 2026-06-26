FROM python:3.12-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    jq \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Pin external scanner versions for reproducible builds.
ARG DNSX_VERSION=1.2.3
ARG NAABU_VERSION=2.6.1

RUN set -eux; \
    ARCH="$(dpkg --print-architecture)"; \
    case "${ARCH}" in \
      amd64) GOARCH="amd64" ;; \
      arm64) GOARCH="arm64" ;; \
      *) echo "Unsupported architecture: ${ARCH}"; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${GOARCH}.zip" -o /tmp/dnsx.zip; \
    curl -fsSL "https://github.com/projectdiscovery/naabu/releases/download/v${NAABU_VERSION}/naabu_${NAABU_VERSION}_linux_${GOARCH}.zip" -o /tmp/naabu.zip; \
    apt-get update && apt-get install -y --no-install-recommends unzip; \
    unzip -q -o /tmp/dnsx.zip dnsx -d /usr/local/bin; \
    unzip -q -o /tmp/naabu.zip naabu -d /usr/local/bin; \
    chmod +x /usr/local/bin/dnsx /usr/local/bin/naabu; \
    rm -f /tmp/dnsx.zip /tmp/naabu.zip; \
    apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

# Vulnerability NSE scripts:
#  - nmap-vulners: maps service versions (-sV) to CVEs via the vulners.com API (needs egress).
#  - vulscan: offline CVE matching against bundled local databases (no internet required).
# Pin to a commit via build args for reproducible builds; defaults track upstream main.
ARG NMAP_VULNERS_REF=master
ARG VULSCAN_REF=master
RUN set -eux; \
    git clone https://github.com/vulnersCom/nmap-vulners.git /usr/share/nmap/scripts/nmap-vulners; \
    git -C /usr/share/nmap/scripts/nmap-vulners checkout "${NMAP_VULNERS_REF}"; \
    git clone https://github.com/scipag/vulscan.git /usr/share/nmap/scripts/vulscan; \
    git -C /usr/share/nmap/scripts/vulscan checkout "${VULSCAN_REF}"; \
    rm -rf /usr/share/nmap/scripts/nmap-vulners/.git /usr/share/nmap/scripts/vulscan/.git; \
    nmap --script-updatedb

# Grant raw-socket capabilities to the scanner binaries via file capabilities so
# host discovery / SYN scans / OS detection work as the non-root 'scanner' user.
# (A container-level --cap-add is NOT inherited by a non-root process on its own.)
RUN set -eux; \
    apt-get update && apt-get install -y --no-install-recommends libcap2-bin; \
    setcap cap_net_raw,cap_net_admin+eip /usr/local/bin/naabu; \
    setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap; \
    apt-get purge -y libcap2-bin && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY scanner /app/scanner

RUN useradd --create-home --shell /usr/sbin/nologin scanner && \
    mkdir -p /app/scanner/output /app/scanner/state && \
    chown -R scanner:scanner /app

USER scanner

VOLUME ["/app/scanner/inputs", "/app/scanner/output", "/app/scanner/state", "/app/scanner/config"]

ENTRYPOINT ["python", "-m", "scanner.main"]
CMD ["--config", "scanner/config/default.yaml"]
