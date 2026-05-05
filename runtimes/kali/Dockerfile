# Kali Factory runtime image.
#
# Goal: maximize the OSINT/recon userland an AI agent can reach while purging
# anything actively offensive (exploit frameworks, cred attacks, MITM/spoofing,
# C2, payload generators, wireless attack tooling).
#
# Three-layer defense — keep this Dockerfile in sync with:
#   - runtimes/kali/tools.json        (declarative manifest)
#   - src/kali_factory/policy/allowlist.py  (Python constants)
#
# Tools are grouped by what they're for. Anything dual-use is included only
# when its passive / read-only mode is the meaningful one — argument shaping
# happens at the job-schema layer.

FROM kalilinux/kali-rolling

LABEL kali-factory.runtime="kali"
LABEL kali-factory.image-version="kali-rolling-2026-q2"
LABEL kali-factory.scope="osint-recon-only"

ENV DEBIAN_FRONTEND=noninteractive

# ─── Allowlisted apt installs ──────────────────────────────────────────────
# All of these are either passive, read-only, or have safe-default invocations
# that the wired job types enforce. Run as a single layer to keep the image
# small.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        # DNS / subdomain / asset discovery (passive sources + bulk resolve)
        amass subfinder massdns \
        dnsutils dnsenum dnsrecon fierce \
        whois \
        # Web fingerprinting (passive signature matching)
        whatweb wafw00f \
        # Modern web crawling / dir enum (rate-limited via job schemas)
        gobuster wfuzz ffuf feroxbuster dirsearch \
        # ProjectDiscovery suite (modern recon)
        httpx-toolkit dnsx naabu katana \
        # Visual recon (browser screenshots of targets)
        gowitness \
        # Generic network info (read-only / passive)
        nmap traceroute mtr-tiny \
        # Packet capture / pcap analysis (read-only without cap_net_raw)
        tcpdump tshark \
        # Network plumbing (the agent needs these to move data around)
        netcat-openbsd socat openssh-client \
        wget curl httpie aria2 \
        rsync \
        # TLS / SSL audit (read-only)
        sslscan sslyze openssl ca-certificates \
        # OSINT frameworks
        theharvester recon-ng spiderfoot \
        # Traffic interception (passive observation only)
        mitmproxy \
        # Secret / leak scanning
        trufflehog \
        # File / forensic analysis
        binwalk foremost bulk-extractor \
        libimage-exiftool-perl file \
        p7zip-full unzip \
        # PDF / doc analysis
        poppler-utils \
        # Data manipulation
        jq ripgrep tree pandoc xmlstarlet \
        # Static code analysis
        shellcheck yamllint \
        # Languages (tool runtime + the agent's own scripting)
        python3-pip python3-venv python3-aiohttp python3-pydantic \
        nodejs npm \
        # General
        git ca-certificates && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ─── Pip-installed tools ────────────────────────────────────────────────────
# Python-only OSINT/recon tools not packaged in Kali apt.
RUN pip install --no-cache-dir --break-system-packages \
        linkfinder \
        secretfinder \
        arjun \
        paramspider \
        sherlock-project \
        holehe \
        maigret \
        yq

# ─── Go binary downloads ────────────────────────────────────────────────────
# A few high-value tools that ship as static Go binaries.
RUN ARCH=$(dpkg --print-architecture) && \
    case "$ARCH" in \
      arm64) GOARCH=arm64 ;; \
      amd64) GOARCH=amd64 ;; \
      *) echo "unsupported arch $ARCH" && exit 1 ;; \
    esac && \
    # nuclei (templated scanner — restricted to safe template dirs by job schemas)
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.3.0_linux_${GOARCH}.zip" -o /tmp/nuclei.zip && \
    cd /tmp && unzip -q nuclei.zip && mv nuclei /usr/local/bin/nuclei && rm -f /tmp/nuclei.zip && \
    /usr/local/bin/nuclei -version && \
    # gitleaks (git secret scanner)
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_8.21.2_linux_${GOARCH}.tar.gz" -o /tmp/gitleaks.tar.gz && \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks && \
    rm -f /tmp/gitleaks.tar.gz && \
    /usr/local/bin/gitleaks version

# ─── CRITICAL: explicit purge of anything offensive ─────────────────────────
# Belt-and-suspenders. Most of these aren't pulled by our installs, but we run
# this anyway so a future apt change or a metapackage drag-in can never sneak
# something offensive into a built image.
RUN apt-get update && \
    apt-get remove -y --purge --autoremove \
        # Exploit / payload frameworks
        metasploit-framework \
        sqlmap \
        commix \
        xsser \
        weevely \
        beef-xss \
        set \
        # Credential cracking
        hashcat hashcat-utils \
        john john-data \
        hydra hydra-gtk \
        medusa ncrack \
        patator \
        kerbrute \
        # Wireless attacks
        aircrack-ng \
        kismet \
        reaver \
        wifite \
        # Active MITM / network spoofing
        ettercap-text-only ettercap-graphical \
        bettercap \
        mitm6 \
        dsniff \
        dnschef \
        # Web app attack scanners (noisy / signature-active)
        nikto \
        wpscan \
        # Post-exploitation / AD attack
        responder \
        crackmapexec \
        evil-winrm \
        bloodhound \
        impacket-scripts \
        # Exploit databases
        exploitdb \
        # Tunneling / pivoting (offensive context)
        chisel \
        # Misc offensive
        thc-ipv6 \
        2>/dev/null || true && \
    rm -rf /var/lib/apt/lists/*

# Tools manifest baked into the image — the in-container MCP server (and any
# defensive verifier) reads from here.
COPY tools.json /etc/parallel-os/tools.json

# Run as non-root
RUN useradd -r -u 65534 -g 65534 -s /usr/sbin/nologin -d /work agent || true
RUN mkdir -p /work && chown 65534:65534 /work

USER 65534:65534
WORKDIR /work

# Default: print version manifest. Real jobs pass an explicit cmd.
CMD ["python3", "-c", "import json; m=json.load(open('/etc/parallel-os/tools.json')); print(json.dumps({'runtime':m['runtime'],'image_version':m['image_version'],'tool_count':len(m.get('tools',{})), 'shell_allowlist_count':len(m.get('shell_allowlist',[]))}))"]
