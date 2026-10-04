# Running an swf app on Hetzner

Step-by-step guide for a Hetzner Cloud server in Germany (EU data protection). It takes about an hour
the first time. Commands run on your own computer are marked **(laptop)**; everything else runs on the
server. A CX22 (2 vCPU, 4 GB RAM) is plenty for a small multi-user app.

---

## 1. Create the server

1. In the [Hetzner Cloud Console](https://console.hetzner.cloud/), create a project, then **Add Server**:
   - Location: **Falkenstein** or **Nuremberg** (Germany)
   - Image: **Ubuntu 24.04**
   - Type: **CX22** (or larger if your app needs it)
   - SSH key: add your public key. **(laptop)** If you have none: `ssh-keygen -t ed25519`, then paste the contents of
     `~/.ssh/id_ed25519.pub`.
   - Do not set a root password.
2. **Firewalls → Create Firewall**, inbound rules only:
   - TCP 22 (SSH). Better still, limit it to your home IP.
   - TCP 80 (HTTP, needed for the certificate and for the redirect to HTTPS)
   - TCP 443 and UDP 443 (HTTPS and HTTP/3)

   Apply it to the server. Everything else is blocked. This firewall sits outside the server, so Docker cannot
   bypass it.
3. At your domain registrar, create an **A record** (and an **AAAA record** for IPv6) for your app domain, for
   example `app.yourdomain.de`, pointing at the server's IP addresses.

## 2. Secure the server

**(laptop)** `ssh root@SERVER_IP`, then:

```bash
# A normal user for day-to-day work
adduser --disabled-password --gecos "" deploy
usermod -aG sudo deploy
mkdir -p /home/deploy/.ssh && cp ~/.ssh/authorized_keys /home/deploy/.ssh/
chown -R deploy:deploy /home/deploy/.ssh && chmod 700 /home/deploy/.ssh
passwd deploy            # needed for sudo; store it in your password manager

# SSH: keys only, no root login
cat > /etc/ssh/sshd_config.d/10-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
EOF
systemctl restart ssh

# Automatic security updates (reboots at 04:00 if a kernel update needs it)
apt update && apt -y upgrade
apt -y install unattended-upgrades
dpkg-reconfigure -f noninteractive unattended-upgrades
cat > /etc/apt/apt.conf.d/52auto-reboot <<'EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
EOF
```

Before you close this window, open a **second** terminal and check that `ssh deploy@SERVER_IP` works.

## 3. Install Docker

As `deploy`:

```bash
sudo apt -y install ca-certificates curl git restic
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update && sudo apt -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker deploy   # then log out and back in
```

## 4. Configure and start the app

```bash
git clone <your repository URL> ~/app
cd ~/app/deploy
cp .env.example .env
chmod 600 .env
openssl rand -hex 32                          # paste as POSTGRES_PASSWORD
openssl rand -base64 32 | tr '+/' '-_'        # paste as MASTER_KEY
nano .env                                     # also set APP_DOMAIN, ACME_EMAIL and your app's folders
```

Store `MASTER_KEY` and `POSTGRES_PASSWORD` in your password manager. **If you lose `MASTER_KEY`, every stored key and
2FA secret is lost, and all users must be reset.** Keep it apart from the database backups.

```bash
docker compose up -d --build
docker compose ps                    # all three services "running" / "healthy"
docker compose logs -f caddy         # wait for "certificate obtained successfully", then Ctrl+C
```

Open `https://<APP_DOMAIN>/api/health`. It should show `{"status":"ok"}`.

Create your own admin account. The one-time password is printed once:

```bash
docker compose exec backend sh -c 'python -m "$APP_PACKAGE.cli" create-admin <your-username>'
```

Sign in at `https://<APP_DOMAIN>`, set up your authenticator app, choose your password and accept the terms.

## 5. Encrypted backups to a Storage Box

1. In the Hetzner Console, order a **Storage Box** (BX11 is plenty) in Germany. Under its settings, enable
   **SSH support**, and note the username (`u123456`) and host (`u123456.your-storagebox.de`).
2. Give the server an SSH key for the Storage Box (Storage Boxes use port 23):

   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/storagebox -N ""
   cat ~/.ssh/storagebox.pub | ssh -p 23 u123456@u123456.your-storagebox.de install-ssh-key
   cat >> ~/.ssh/config <<'EOF'
   Host u123456.your-storagebox.de
     Port 23
     IdentityFile ~/.ssh/storagebox
   EOF
   ```

3. In `deploy/.env`, set `RESTIC_REPOSITORY=sftp:u123456@u123456.your-storagebox.de:/backups/app`,
   a long `RESTIC_PASSWORD` (`openssl rand -base64 32`), and `BACKUP_KEEP_DAYS` to the same value as
   `RetentionPolicy(backup_days=...)` in your app. Store the password in your password manager as well.
4. Create the repository and run the first backup:

   ```bash
   cd ~/app/deploy
   set -a; source .env; set +a
   restic init
   chmod +x backup.sh && ./backup.sh
   ```

5. Run it every night at 03:00:

   ```bash
   (crontab -l 2>/dev/null; echo "0 3 * * * $HOME/app/deploy/backup.sh >> $HOME/backup.log 2>&1") | crontab -
   ```

Backups are kept for `BACKUP_KEEP_DAYS` days, matching the retention promise of your app. They are encrypted on
the server before they leave it, so Hetzner cannot read them.

**Test a restore** once now, and again every few months:

```bash
set -a; source .env; set +a
restic snapshots
restic dump latest app.dump > /tmp/restore.dump
docker compose exec -T db pg_restore -U app -d app --clean --if-exists < /tmp/restore.dump   # overwrites live data!
rm /tmp/restore.dump
```

## 6. Updating the app

```bash
cd ~/app && git pull
cd deploy && docker compose up -d --build
```

Database migrations run automatically when the back end starts.

## Checklist

- [ ] Hetzner firewall allows only 22, 80 and 443
- [ ] SSH works with keys only; root login is off
- [ ] Unattended upgrades are on
- [ ] `https://<APP_DOMAIN>` shows a valid certificate
- [ ] `MASTER_KEY`, `POSTGRES_PASSWORD` and `RESTIC_PASSWORD` are in your password manager
- [ ] A nightly backup has run (`restic snapshots`) and a restore has been tested
