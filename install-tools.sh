#!/usr/bin/env bash
# install-tools.sh — Install all security tools hex-agent wraps, on Ubuntu 22.04+ / Debian 12+.
#
# Idempotent: safe to re-run. Skips already-installed tools.
# Usage:
#   sudo ./install-tools.sh                  # install everything
#   sudo ./install-tools.sh --no-cloud       # skip prowler/scoutsuite
#   sudo ./install-tools.sh --no-fuzz        # skip afl++
#   sudo ./install-tools.sh --check          # report what's missing, install nothing
#
# Tools installed (31 wrappers + dependencies):
#   recon:    nmap masscan subfinder dnsx httpx amass naabu whatweb rustscan
#   web:      nuclei ffuf gobuster feroxbuster dirb nikto sqlmap wpscan
#             katana gau waybackurls dalfox arjun dirsearch
#   tls:      testssl.sh sslyze sslscan
#   creds:    hydra hashcat john kerbrute responder
#   ad:       netexec(nxc) impacket bloodhound.py crackmapexec evil-winrm
#             enum4linux-ng smbmap mitm6
#   sast:     semgrep trivy gitleaks
#   re/bin:   checksec ropper radare2 afl++
#   cloud:    prowler scoutsuite
#   pcap/nsm: tshark suricata zeek
#   exploit:  searchsploit metasploit-framework msfvenom
#   utils:    jq curl wget git python3-pip pipx go ruby unzip

set -euo pipefail

CHECK_ONLY=0
SKIP_CLOUD=0
SKIP_FUZZ=0
SKIP_MSF=0
for arg in "$@"; do
    case "$arg" in
        --check) CHECK_ONLY=1 ;;
        --no-cloud) SKIP_CLOUD=1 ;;
        --no-fuzz) SKIP_FUZZ=1 ;;
        --no-msf) SKIP_MSF=1 ;;
        -h|--help)
            sed -n '2,24p' "$0"
            exit 0
            ;;
        *) echo "unknown arg: $arg" >&2; exit 2 ;;
    esac
done

C_INFO="\033[1;36m"; C_OK="\033[1;32m"; C_WARN="\033[1;33m"; C_ERR="\033[1;31m"; C_OFF="\033[0m"
log()  { echo -e "${C_INFO}[*]${C_OFF} $*"; }
ok()   { echo -e "${C_OK}[+]${C_OFF} $*"; }
warn() { echo -e "${C_WARN}[!]${C_OFF} $*"; }
err()  { echo -e "${C_ERR}[-]${C_OFF} $*"; }

if [[ "${EUID}" -ne 0 && ${CHECK_ONLY} -eq 0 ]]; then
    err "must run as root (sudo). Re-run with: sudo $0"
    exit 1
fi

# --- preflight ---------------------------------------------------------------
. /etc/os-release
case "${ID:-}" in
    ubuntu|debian|kali|pop|linuxmint) ;;
    *) warn "unsupported distro: ${ID:-unknown} — expect breakage" ;;
esac

REAL_USER="${SUDO_USER:-${USER:-root}}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
GO_BIN="${REAL_HOME}/go/bin"
PIPX_BIN="${REAL_HOME}/.local/bin"
OPT_DIR="/opt"

have() { command -v "$1" >/dev/null 2>&1; }
as_user() { sudo -u "$REAL_USER" -H bash -c "$*"; }

declare -a MISSING=()
declare -a INSTALLED=()
mark() { if have "$1"; then INSTALLED+=("$1"); else MISSING+=("$1"); fi; }

# --- check mode --------------------------------------------------------------
if [[ ${CHECK_ONLY} -eq 1 ]]; then
    log "checking installed tools..."
    for t in nmap masscan subfinder dnsx httpx amass naabu whatweb rustscan \
             nuclei ffuf gobuster feroxbuster dirb nikto sqlmap wpscan \
             katana gau waybackurls dalfox arjun dirsearch \
             testssl.sh sslyze sslscan \
             hydra hashcat john kerbrute responder \
             nxc impacket-secretsdump bloodhound-python crackmapexec evil-winrm \
             enum4linux-ng smbmap mitm6 \
             semgrep trivy gitleaks \
             checksec ropper r2 afl-fuzz \
             prowler scout \
             tshark suricata zeek \
             searchsploit msfconsole msfvenom; do
        if have "$t"; then ok "$t"; else err "$t (missing)"; fi
    done
    exit 0
fi

# --- 1. apt base -------------------------------------------------------------
log "updating apt and installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
    ca-certificates curl wget git jq unzip build-essential pkg-config \
    python3 python3-pip python3-venv pipx \
    ruby ruby-dev rubygems \
    golang-go \
    libssl-dev libffi-dev libpcap-dev \
    nmap masscan whatweb nikto sqlmap dirb gobuster ffuf \
    hydra john hashcat \
    tshark suricata zeek \
    radare2 \
    libimage-exiftool-perl

ok "apt base done"

# Ensure pipx path for the calling user
as_user "pipx ensurepath >/dev/null 2>&1 || true"

# --- 2. golang tools (ProjectDiscovery + amass) ------------------------------
if ! have go; then err "go missing — aborting"; exit 1; fi

install_go() {
    local pkg="$1" bin="$2"
    if have "$bin"; then ok "$bin already installed"; return; fi
    log "go install $pkg"
    as_user "GOPATH=$REAL_HOME/go GOBIN=$GO_BIN go install $pkg@latest"
    ln -sf "$GO_BIN/$bin" "/usr/local/bin/$bin"
    ok "$bin installed"
}

install_go github.com/projectdiscovery/subfinder/v2/cmd/subfinder subfinder
install_go github.com/projectdiscovery/dnsx/cmd/dnsx                dnsx
install_go github.com/projectdiscovery/httpx/cmd/httpx              httpx
install_go github.com/projectdiscovery/naabu/v2/cmd/naabu           naabu
install_go github.com/projectdiscovery/nuclei/v3/cmd/nuclei         nuclei
install_go github.com/owasp-amass/amass/v4/...                      amass
install_go github.com/ffuf/ffuf/v2                                  ffuf

# nuclei templates
log "updating nuclei templates..."
as_user "nuclei -update-templates -silent" || warn "nuclei template update failed"

# --- 3. feroxbuster ----------------------------------------------------------
if ! have feroxbuster; then
    log "installing feroxbuster..."
    bash -c "curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash -s -- --bin /usr/local/bin"
    ok "feroxbuster installed"
else
    ok "feroxbuster present"
fi

# --- 4. python tools via pipx -----------------------------------------------
pipx_install() {
    local pkg="$1" probe="$2"
    if have "$probe"; then ok "$probe already installed"; return; fi
    log "pipx install $pkg"
    as_user "pipx install --force $pkg" || warn "pipx install $pkg failed"
}

# netexec (nxc) — modern CME successor
pipx_install netexec nxc
# impacket suite (impacket-secretsdump etc.)
pipx_install impacket impacket-secretsdump
# bloodhound.py ingestor
pipx_install bloodhound bloodhound-python
# semgrep
pipx_install semgrep semgrep
# sslyze
pipx_install sslyze sslyze
# wpscan is a ruby gem (see below)
# scoutsuite (cloud) — heavy
if [[ ${SKIP_CLOUD} -eq 0 ]]; then
    pipx_install scoutsuite scout
    pipx_install prowler prowler
else
    warn "skipping cloud tools (--no-cloud)"
fi

# checksec.sh
if ! have checksec; then
    log "installing checksec.sh..."
    curl -sL https://raw.githubusercontent.com/slimm609/checksec/master/checksec -o /usr/local/bin/checksec
    chmod +x /usr/local/bin/checksec
    ok "checksec installed"
else
    ok "checksec present"
fi

# ropper
pipx_install ropper ropper

# pipx for additional python tools
pipx_install enum4linux-ng enum4linux-ng
pipx_install smbmap smbmap
pipx_install mitm6 mitm6

# crackmapexec (legacy but some scripts still expect it)
if ! have crackmapexec; then
    apt-get install -y crackmapexec 2>/dev/null || \
        as_user "pipx install --force crackmapexec" || warn "crackmapexec install failed"
fi

# responder (apt provides it on Kali/Ubuntu universe)
if ! have responder; then
    if apt-get install -y responder 2>/dev/null; then
        ok "responder installed (apt)"
    else
        log "installing responder from source..."
        git clone --depth 1 https://github.com/lgandx/Responder.git "$OPT_DIR/Responder"
        cat >/usr/local/bin/responder <<'EOF'
#!/usr/bin/env bash
exec python3 /opt/Responder/Responder.py "$@"
EOF
        chmod +x /usr/local/bin/responder
        ok "responder installed (source)"
    fi
else
    ok "responder present"
fi

# evil-winrm (ruby gem)
if ! have evil-winrm; then
    log "installing evil-winrm gem..."
    gem install --no-document evil-winrm
    ok "evil-winrm installed"
else
    ok "evil-winrm present"
fi

# rustscan
if ! have rustscan; then
    log "installing rustscan..."
    RS_URL=$(curl -fsSL https://api.github.com/repos/RustScan/RustScan/releases/latest \
        | jq -r '.assets[] | select(.name | test("amd64.deb$")) | .browser_download_url' | head -1)
    if [[ -n "$RS_URL" ]]; then
        tmp=$(mktemp -d); curl -sL "$RS_URL" -o "$tmp/rustscan.deb"
        apt-get install -y "$tmp/rustscan.deb" || dpkg -i "$tmp/rustscan.deb" || warn "rustscan install failed"
        rm -rf "$tmp"
        ok "rustscan installed"
    else
        warn "rustscan release URL not found"
    fi
else
    ok "rustscan present"
fi

# go-based web recon: katana, gau, waybackurls, dalfox
install_go github.com/projectdiscovery/katana/cmd/katana             katana
install_go github.com/lc/gau/v2/cmd/gau                              gau
install_go github.com/tomnomnom/waybackurls                          waybackurls
install_go github.com/hahwul/dalfox/v2                               dalfox

# arjun (parameter discovery) — pipx
pipx_install arjun arjun

# dirsearch — pipx
pipx_install dirsearch dirsearch

# --- 6b. metasploit framework ------------------------------------------------
if [[ ${SKIP_MSF} -eq 0 ]]; then
    if ! have msfconsole; then
        log "installing metasploit-framework (rapid7 installer)..."
        # Try apt first (kali/parrot have it), else use rapid7 omnibus installer
        if apt-get install -y metasploit-framework 2>/dev/null; then
            ok "metasploit installed (apt)"
        else
            curl -fsSL https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb \
                -o /tmp/msfinstall
            curl -fsSL https://apt.metasploit.com/metasploit-framework.gpg.key \
                | gpg --dearmor -o /usr/share/keyrings/metasploit.gpg
            echo "deb [signed-by=/usr/share/keyrings/metasploit.gpg] https://apt.metasploit.com/ $(lsb_release -cs 2>/dev/null || echo focal) main" \
                > /etc/apt/sources.list.d/metasploit.list
            apt-get update -y
            apt-get install -y metasploit-framework || warn "metasploit install failed (try manual)"
        fi
        # Initialize msfdb (best effort, non-interactive)
        if have msfdb; then
            as_user "msfdb init" >/dev/null 2>&1 || warn "msfdb init failed (run manually as your user)"
        fi
    else
        ok "metasploit present"
    fi
else
    warn "skipping metasploit (--no-msf)"
fi

# --- 5. ruby gems ------------------------------------------------------------
if ! have wpscan; then
    log "installing wpscan gem..."
    gem install --no-document wpscan
    ok "wpscan installed"
else
    ok "wpscan present"
fi

# --- 6. github releases / source builds -------------------------------------
# kerbrute
if ! have kerbrute; then
    log "installing kerbrute..."
    KERB_URL=$(curl -fsSL https://api.github.com/repos/ropnop/kerbrute/releases/latest \
        | jq -r '.assets[] | select(.name | test("linux_amd64$")) | .browser_download_url' | head -1)
    if [[ -n "$KERB_URL" ]]; then
        curl -sL "$KERB_URL" -o /usr/local/bin/kerbrute
        chmod +x /usr/local/bin/kerbrute
        ok "kerbrute installed"
    else
        warn "kerbrute release URL not found"
    fi
else
    ok "kerbrute present"
fi

# gitleaks
if ! have gitleaks; then
    log "installing gitleaks..."
    GL_URL=$(curl -fsSL https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
        | jq -r '.assets[] | select(.name | test("linux_x64.tar.gz$")) | .browser_download_url' | head -1)
    if [[ -n "$GL_URL" ]]; then
        tmp=$(mktemp -d); curl -sL "$GL_URL" | tar -xz -C "$tmp"
        install -m 0755 "$tmp/gitleaks" /usr/local/bin/gitleaks
        rm -rf "$tmp"
        ok "gitleaks installed"
    else
        warn "gitleaks release URL not found"
    fi
else
    ok "gitleaks present"
fi

# trivy (aquasec apt repo)
if ! have trivy; then
    log "installing trivy..."
    curl -fsSL https://aquasecurity.github.io/trivy-repo/deb/public.key \
        | gpg --dearmor -o /usr/share/keyrings/trivy.gpg
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
        > /etc/apt/sources.list.d/trivy.list
    apt-get update -y
    apt-get install -y trivy
    ok "trivy installed"
else
    ok "trivy present"
fi

# testssl.sh
if ! have testssl.sh; then
    log "installing testssl.sh..."
    git clone --depth 1 https://github.com/drwetter/testssl.sh.git "$OPT_DIR/testssl.sh"
    ln -sf "$OPT_DIR/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh
    ok "testssl.sh installed"
else
    ok "testssl.sh present"
fi

# sslscan (apt has it on most ubuntu)
if ! have sslscan; then
    apt-get install -y sslscan || warn "sslscan apt install failed"
fi

# searchsploit (exploit-db)
if ! have searchsploit; then
    log "installing exploitdb (searchsploit)..."
    git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git "$OPT_DIR/exploitdb"
    ln -sf "$OPT_DIR/exploitdb/searchsploit" /usr/local/bin/searchsploit
    ok "searchsploit installed"
else
    ok "searchsploit present"
fi

# afl++ (fuzzer)
if [[ ${SKIP_FUZZ} -eq 0 ]]; then
    if ! have afl-fuzz; then
        log "installing AFL++ (this can take several minutes)..."
        apt-get install -y --no-install-recommends \
            clang llvm lld python3-dev \
            automake cmake flex bison libglib2.0-dev libpixman-1-dev \
            cargo libstdc++-12-dev || true
        git clone --depth 1 https://github.com/AFLplusplus/AFLplusplus.git "$OPT_DIR/AFLplusplus" || true
        (cd "$OPT_DIR/AFLplusplus" && make distrib && make install) || warn "AFL++ build failed (skip with --no-fuzz)"
    else
        ok "afl-fuzz present"
    fi
else
    warn "skipping AFL++ (--no-fuzz)"
fi

# --- 7. final summary --------------------------------------------------------
log "verifying installed binaries..."
declare -a TOOLS=(
    nmap masscan subfinder dnsx httpx amass naabu whatweb rustscan
    nuclei ffuf gobuster feroxbuster dirb nikto sqlmap wpscan
    katana gau waybackurls dalfox arjun dirsearch
    testssl.sh sslyze sslscan
    hydra hashcat john kerbrute responder
    nxc impacket-secretsdump bloodhound-python crackmapexec evil-winrm
    enum4linux-ng smbmap mitm6
    semgrep trivy gitleaks
    checksec ropper r2
    tshark suricata zeek
    searchsploit
)
[[ ${SKIP_FUZZ} -eq 0 ]] && TOOLS+=(afl-fuzz)
[[ ${SKIP_CLOUD} -eq 0 ]] && TOOLS+=(prowler scout)
[[ ${SKIP_MSF} -eq 0 ]] && TOOLS+=(msfconsole msfvenom)

PRESENT=0; ABSENT=0
for t in "${TOOLS[@]}"; do
    if have "$t"; then ok "$t"; PRESENT=$((PRESENT+1))
    else err "$t MISSING"; ABSENT=$((ABSENT+1))
    fi
done

echo
log "installed: ${PRESENT} / ${#TOOLS[@]}    missing: ${ABSENT}"
echo
log "next steps:"
echo "  1. add ${GO_BIN} and ${PIPX_BIN} to your PATH:"
echo "       echo 'export PATH=\$HOME/go/bin:\$HOME/.local/bin:\$PATH' >> ~/.bashrc"
echo "  2. set API keys (chaos, github, shodan) for subfinder/amass providers in ~/.config/subfinder/provider-config.yaml"
echo "  3. run: hex --authorized-pentest --scope example.com"
echo
[[ $ABSENT -eq 0 ]] && ok "all tools installed" || warn "${ABSENT} tool(s) missing — review log above"
