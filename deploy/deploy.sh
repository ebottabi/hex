#!/usr/bin/env bash
# deploy.sh — runs on the target Ubuntu server. Idempotent.
#
# hex is a CLI tool: this script installs the binary into /usr/local/bin
# and runs install-tools.sh to provision the security toolchain. No system
# user is created and no systemd unit is installed — hex is invoked
# interactively (e.g. over SSH) or by ad-hoc scripts.
set -euo pipefail

BIN_NAME="hex"
INSTALL_DIR="/usr/local/bin"
BACKUP_DIR="/var/backups"

C_INFO="\033[1;36m"; C_OK="\033[1;32m"; C_WARN="\033[1;33m"; C_ERR="\033[1;31m"; C_OFF="\033[0m"
log()  { echo -e "${C_INFO}[*]${C_OFF} $*"; }
ok()   { echo -e "${C_OK}[+]${C_OFF} $*"; }
warn() { echo -e "${C_WARN}[!]${C_OFF} $*"; }
err()  { echo -e "${C_ERR}[-]${C_OFF} $*"; }

if [[ "$EUID" -ne 0 ]]; then
    err "must run as root"
    exit 1
fi

HERE=$(cd "$(dirname "$0")" && pwd)

# 1. install binary (backup previous for rollback)
install -d -m 0755 "$BACKUP_DIR"
if [[ -f "$INSTALL_DIR/$BIN_NAME" ]]; then
    install -m 0755 "$INSTALL_DIR/$BIN_NAME" "$BACKUP_DIR/hex.previous" || true
    ok "previous binary backed up -> $BACKUP_DIR/hex.previous"
fi
log "installing binary -> $INSTALL_DIR/$BIN_NAME"
install -m 0755 "$HERE/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
ok "binary version: $($INSTALL_DIR/$BIN_NAME --version 2>/dev/null || echo unknown)"

# 2. run install-tools.sh (best-effort: optional tools may be missing on
#    minimal Ubuntu base images and that's fine).
if [[ -x "$HERE/install-tools.sh" ]]; then
    log "running install-tools.sh (this may take a while)..."
    "$HERE/install-tools.sh" || warn "install-tools.sh returned non-zero (some optional tools missing)"
else
    warn "install-tools.sh not in bundle — skipping tools install"
fi

# 3. final sanity check
if "$INSTALL_DIR/$BIN_NAME" --version >/dev/null 2>&1; then
    ok "hex is installed and runnable"
else
    err "hex installed but --version failed"
    exit 1
fi

log "deploy complete."
echo "  • run:       hex --help"
echo "  • providers: export GROQ_API_KEY=... (or OPENAI_API_KEY / ANTHROPIC_API_KEY / ...)"
echo "  • pentest:   hex --authorized-pentest --scope <target> --report ./report.md"
echo "  • rollback:  install -m 0755 $BACKUP_DIR/hex.previous $INSTALL_DIR/$BIN_NAME"
