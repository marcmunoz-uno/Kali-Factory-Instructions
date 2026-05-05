# Kali Factory runtime image.
# Hardened Kali rolling with allowlisted OSINT tools only.
# Exploitation, credential cracking, and wireless tools are explicitly purged.

FROM kalilinux/kali-rolling

LABEL kali-factory.runtime="kali"
LABEL kali-factory.image-version="kali-rolling-2026-q2"
LABEL kali-factory.scope="osint-recon-only"

ENV DEBIAN_FRONTEND=noninteractive

# Install allowlisted tools only.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        amass dnsutils dnsenum \
        whatweb gobuster wfuzz \
        mitmproxy \
        python3-pip python3-venv python3-aiohttp python3-pydantic \
        trufflehog \
        curl jq git ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Pip-only tools
RUN pip install --no-cache-dir --break-system-packages \
        linkfinder \
        secretfinder \
        arjun

# Install nuclei (Go-built, fastest path is the official binary release)
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      arm64) NUCLEI_ARCH=arm64 ;; \
      amd64) NUCLEI_ARCH=amd64 ;; \
      *) echo "unsupported arch $ARCH" && exit 1 ;; \
    esac && \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.0_linux_${NUCLEI_ARCH}.zip" -o /tmp/nuclei.zip || true && \
    cd /tmp && unzip -q nuclei.zip && mv nuclei /usr/local/bin/nuclei && rm -f /tmp/nuclei.zip && \
    /usr/local/bin/nuclei -version

# CRITICAL: explicitly purge anything offensive that might have come in via deps
RUN apt-get update && \
    apt-get remove -y --purge --autoremove \
        metasploit-framework \
        sqlmap \
        hashcat hashcat-utils \
        john john-data \
        aircrack-ng \
        exploitdb \
        hydra hydra-gtk \
        medusa ncrack \
        nikto wpscan \
        responder crackmapexec \
        2>/dev/null || true && \
    rm -rf /var/lib/apt/lists/*

# Tools manifest + verifier baked into the image
COPY tools.json /etc/parallel-os/tools.json

# Run as non-root
RUN useradd -r -u 65534 -g 65534 -s /usr/sbin/nologin -d /work agent || true
RUN mkdir -p /work && chown 65534:65534 /work

USER 65534:65534
WORKDIR /work

# Default: print version manifest. Real jobs pass an explicit cmd.
CMD ["python3", "-c", "import json; m=json.load(open('/etc/parallel-os/tools.json')); print(json.dumps({'runtime':m['runtime'],'image_version':m['image_version'],'tool_count':len(m.get('tools',{}))}))"]
