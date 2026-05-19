# Deployment

GitOps pipeline that builds hex-agent for Ubuntu and deploys it to a server.

## Architecture

```
push main / tag v*           ┌── workflow_dispatch ──┐
       │                     │                       │
       ▼                     ▼                       ▼
 GitHub Actions: build ──► artifact.tar.gz ──► GitHub Actions: deploy
                                                       │
                                                       ▼
                                                ssh + bash deploy.sh
                                                       │
                                          ┌────────────┴────────────┐
                                          ▼                         ▼
                                   install-tools.sh           systemd unit
                                   (40+ Kali tools)           (hex-agent.service)
```

## Files

| File | Purpose |
|---|---|
| `hex-agent.service` | systemd unit (hardened, CAP_NET_RAW for nmap) |
| `deploy.sh` | Runs on server: user setup, binary install, install-tools.sh, systemd reload, health check |
| `../.github/workflows/build-deploy.yml` | The GitOps workflow |
| `../install-tools.sh` | Kali toolset installer (40+ tools, idempotent) |

## Required GitHub secrets

| Secret | Description |
|---|---|
| `DEPLOY_HOST` | Server hostname or IP |
| `DEPLOY_USER` | SSH user with sudo (NOPASSWD recommended) |
| `DEPLOY_SSH_KEY` | Private ed25519 key |

Set at `Settings → Secrets and variables → Actions`.

## One-time server prep

```bash
sudo useradd -m -s /bin/bash deployer
sudo mkdir -p /home/deployer/.ssh
echo "ssh-ed25519 AAAA... your-deploy-pubkey" | sudo tee /home/deployer/.ssh/authorized_keys
sudo chown -R deployer:deployer /home/deployer/.ssh
sudo chmod 600 /home/deployer/.ssh/authorized_keys
echo "deployer ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/deployer
```

## Triggers

| Trigger | Behavior |
|---|---|
| Push to `main` | Build + deploy |
| Tag `v*` | Build + deploy + GitHub Release |
| Manual (workflow_dispatch) | Build always, deploy if checked |

## Local test

```bash
cargo build --release
mkdir -p /tmp/hex-bundle
cp target/release/hex install-tools.sh deploy/hex-agent.service deploy/deploy.sh /tmp/hex-bundle/
sudo /tmp/hex-bundle/deploy.sh
```

## Ops

```bash
systemctl status hex-agent      # health
journalctl -u hex-agent -f      # tail logs
sudo $EDITOR /etc/hex/hex.env   # set API keys, then systemctl restart hex-agent
```

## Rollback

```bash
sudo systemctl stop hex-agent
sudo cp /var/backups/hex.previous /usr/local/bin/hex
sudo systemctl start hex-agent
```

Or re-deploy a previous tag from Actions UI.

## Security

- Dedicated `hex` user, `NoNewPrivileges`, `ProtectSystem=full`, `PrivateTmp`.
- Only `CAP_NET_RAW`/`CAP_NET_ADMIN` granted (nmap/masscan SYN scans).
- API keys in `/etc/hex/hex.env` (mode 0640, owned by `root:hex`).
- Bundle SHA256-verified on the server before execution.
- Use a dedicated deploy key, not a personal SSH key.
