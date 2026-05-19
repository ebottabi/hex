#!/usr/bin/env bash
# deploy.sh — runs on the target Ubuntu server. Idempotent.
set -euo pipefail

BIN_NAME="hex"
SERVICE="hex-agent"
INSTALL_DIR="/usr/local/bin"
DATA_DIR="/var/lib/hex"
LOG_DIR="/var/log/hex"
ETC_DIR="/etc/hex"
USER_NAME="hex"

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

# 1. user + dirs
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
    log "creating system user '$USER_NAME'..."
    useradd --system --create-home --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$USER_NAME"
    ok "user created"
else
    ok "user '$USER_NAME' exists"
fi

install -d -o "$USER_NAME" -g "$USER_NAME" -m 0750 "$DATA_DIR" "$LOG_DIR"
install -d -m 0755 "$ETC_DIR"
if [[ ! -f "$ETC_DIR/hex.env" ]]; then
    cat >"$ETC_DIR/hex.env" <<'EOF'
# hex-agent environment — set API keys here
# GROQ_API_KEY=
# ANTHROPIC_API_KEY=
# OPENAI_API_KEY=
HEX_MAX_COST=5.00
RUST_LOG=info
EOF
    chmod 0640 "$ETC_DIR/hex.env"
    chown root:"$USER_NAME" "$ETC_DIR/hex.env"
fi

# 2. install binary (backup previous for rollback)
if [[ -f "$INSTALL_DIR/$BIN_NAME" ]]; then
    install -m 0755 "$INSTALL_DIR/$BIN_NAME" /var/backups/hex.previous || true
fi
log "installing binary -> $INSTALL_DIR/$BIN_NAME"
install -m 0755 "$HERE/$BIN_NAME" "$INSTALL_DIR/$BIN_NAME"
ok "binary version: $($INSTALL_DIR/$BIN_NAME --version 2>/dev/null || echo unknown)"

# 3. run install-tools.sh
log "running install-tools.sh (this may take a while)..."
if [[ -x "$HERE/install-tools.sh" ]]; then
    "$HERE/install-tools.sh" || warn "install-tools.sh returned non-zero (some optional tools missing)"
else
    warn "install-tools.sh not in bundle — skipping tools install"
fi

# 4. systemd unit
log "installing systemd unit -> /etc/systemd/system/$SERVICE.service"
install -m 0644 "$HERE/hex-agent.service" "/etc/systemd/system/$SERVICE.service"
systemctl daemon-reload
systemctl enable "$SERVICE"
systemctl restart "$SERVICE"
ok "service enabled and (re)started"

# 5. health check
sleep 2
if systemctl is-active --quiet "$SERVICE"; then
    ok "service is active"
else
    err "service failed to start"
    journalctl -u "$SERVICE" --no-pager -n 50
    exit 1
fi

log "deploy complete."
echo "  • status:  systemctl status $SERVICE"
echo "  • logs:    journalctl -u $SERVICE -f"
echo "  • config:  $ETC_DIR/hex.env"
echo "  • data:    $DATA_DIR"
