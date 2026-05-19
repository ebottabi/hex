# Deployment

GitOps pipeline that builds **hex-agent** for Ubuntu and installs it as a CLI
binary on a server. hex is invoked interactively (over SSH) or by ad-hoc
scripts — no system user, no systemd unit, no long-running service.

## Architecture

```
push master / tag v*          ┌── workflow_dispatch ──┐
       │                      │                       │
       ▼                      ▼                       ▼
 GitHub Actions: build ──► artifact.tar.gz ──► GitHub Actions: deploy
                                                       │
                                                       ▼
                                              ssh + sudo bash deploy.sh
                                                       │
                                          ┌────────────┴────────────┐
                                          ▼                         ▼
                            /usr/local/bin/hex             install-tools.sh
                            (CLI binary)                   (40+ Kali tools)
```

## Files

| File | Purpose |
|---|---|
| `deploy.sh` | Runs on server as root: installs `hex` to `/usr/local/bin`, runs `install-tools.sh`, sanity-checks `hex --version`. |
| `../.github/workflows/build-deploy.yml` | The GitOps workflow. |
| `../install-tools.sh` | Kali toolset installer (40+ tools, idempotent). |

## Required GitHub secrets

| Secret | Description |
|---|---|
| `DEPLOY_HOST` | Server hostname or IP |
| `DEPLOY_USER` | SSH user with passwordless sudo |
| `DEPLOY_SSH_KEY` | Private ed25519 key for that user |

Set at *Settings → Secrets and variables → Actions*.

## One-time server prep

```bash
# As an existing admin on the box
sudo useradd -m -s /bin/bash deployer
sudo install -d -m 0700 -o deployer -g deployer /home/deployer/.ssh
echo "ssh-ed25519 AAAA... your-deploy-pubkey" | \
    sudo tee /home/deployer/.ssh/authorized_keys >/dev/null
sudo chown deployer:deployer /home/deployer/.ssh/authorized_keys
sudo chmod 600 /home/deployer/.ssh/authorized_keys
echo "deployer ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/deployer
```

## Triggers

| Trigger | Behavior |
|---|---|
| Push to `master` | Build + deploy |
| Tag `v*` | Build + deploy + GitHub Release |
| Manual (workflow_dispatch) | Build always, deploy if `deploy=true` |

## Local test

```bash
cargo build --release
mkdir -p /tmp/hex-bundle
cp target/release/hex install-tools.sh deploy/deploy.sh /tmp/hex-bundle/
chmod +x /tmp/hex-bundle/hex /tmp/hex-bundle/*.sh
sudo /tmp/hex-bundle/deploy.sh
```

## Using hex on the server

hex is now a normal CLI. SSH in as any user that can read the keys file or
has the env exported, then:

```bash
export GROQ_API_KEY=...
hex                                   # interactive coding assistant
hex --provider groq --model llama-3.3-70b-versatile
hex --authorized-pentest --scope example.com --report ./report.md
```

### Recommended: per-user secrets file

Rather than exporting keys in `~/.bashrc` (where they leak to every child
process), keep them in a 0600 file you source on demand:

```bash
install -d -m 0700 ~/.config/hex
cat > ~/.config/hex/secrets.env <<EOF
GROQ_API_KEY=...
ANTHROPIC_API_KEY=...
EOF
chmod 600 ~/.config/hex/secrets.env

# Source just-in-time
set -a; . ~/.config/hex/secrets.env; set +a
hex
```

## Rollback

`deploy.sh` keeps the previous binary at `/var/backups/hex.previous`:

```bash
sudo install -m 0755 /var/backups/hex.previous /usr/local/bin/hex
hex --version
```

Or re-deploy a previous tag from the Actions UI.

## Security notes

- Bundle SHA256-verified on the server before `deploy.sh` runs.
- Use a dedicated deploy key (ed25519), not a personal SSH key.
- API keys never live in the bundle — they're staged per-user in
  `~/.config/hex/secrets.env` (0600) or exported in the shell that runs hex.
- Optional Kali packages missing from minimal Ubuntu images
  (`zeek`, `suricata`, `radare2`) are skipped rather than failing the
  install — layer extra repos if you need them.
