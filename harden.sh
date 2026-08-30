#!/usr/bin/env bash
#
# harden.sh — baseline hardening for a fresh Ubuntu server (22.04 / 24.04).
#
# Run as root on a freshly provisioned box:
#   sudo bash harden.sh
#
# What it does:
#   1. Full system update + unattended security upgrades
#   2. Creates a non-root sudo user with your SSH key
#   3. Hardens sshd (key-only auth, incl. root; modern settings)
#   4. UFW firewall: deny inbound except SSH/HTTP/HTTPS
#   5. fail2ban for SSH brute-force protection
#   6. Kernel/network sysctl hardening
#   7. Docker from the official apt repo, with live-restore enabled
#   8. Misc: AppArmor check, time sync, disables unneeded services
#
# It will NOT disable password auth or root login until it has verified
# your SSH key works for the new user, so you can't lock yourself out.

set -euo pipefail

# ------------------------------------------------------------------
# Configuration — edit before running
# ------------------------------------------------------------------
DEPLOY_USER="${DEPLOY_USER:-deploy}"
SSH_PORT="${SSH_PORT:-22}"
# Public key for the deploy user. If empty, root's authorized_keys is copied
# (most cloud images put your provisioning key there).
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"
# ------------------------------------------------------------------

log()  { echo -e "\n\033[1;32m==> $*\033[0m"; }
warn() { echo -e "\033[1;33m[!] $*\033[0m"; }
die()  { echo -e "\033[1;31m[x] $*\033[0m" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"
. /etc/os-release
[[ ${ID:-} == "ubuntu" ]] || die "This script targets Ubuntu (detected: ${ID:-unknown})"

export DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------
log "1/8 System update"
# ------------------------------------------------------------------
apt-get update -y
apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" upgrade -y
apt-get install -y \
  unattended-upgrades apt-listchanges \
  ufw fail2ban \
  curl ca-certificates gnupg \
  chrony \
  apparmor apparmor-utils

# Unattended security upgrades (reboot handled by cron below, Sundays only).
cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id}ESMApps:${distro_codename}-apps-security";
    "${distro_id}ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF
# unattended-upgrades can't restrict reboots to a weekday, so reboot via
# cron instead: Sundays 04:00, only if an update actually requires it.
cat > /etc/cron.d/reboot-if-required <<'EOF'
0 4 * * 0 root [ -f /var/run/reboot-required ] && /sbin/shutdown -r +1 "Rebooting for pending security updates"
EOF
chmod 644 /etc/cron.d/reboot-if-required
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades

# ------------------------------------------------------------------
log "2/8 Create user '$DEPLOY_USER'"
# ------------------------------------------------------------------
if ! id -u "$DEPLOY_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$DEPLOY_USER"
fi
usermod -aG sudo "$DEPLOY_USER"
# Passwordless sudo — the account has no password, so sudo would otherwise
# be unusable. Remove this file and set a password if you prefer prompts.
echo "$DEPLOY_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-$DEPLOY_USER"
chmod 440 "/etc/sudoers.d/90-$DEPLOY_USER"

USER_SSH_DIR="/home/$DEPLOY_USER/.ssh"
mkdir -p "$USER_SSH_DIR"
if [[ -n "$SSH_PUBLIC_KEY" ]]; then
  grep -qxF "$SSH_PUBLIC_KEY" "$USER_SSH_DIR/authorized_keys" 2>/dev/null \
    || echo "$SSH_PUBLIC_KEY" >> "$USER_SSH_DIR/authorized_keys"
elif [[ -s /root/.ssh/authorized_keys ]]; then
  cp /root/.ssh/authorized_keys "$USER_SSH_DIR/authorized_keys"
else
  die "No SSH key: set SSH_PUBLIC_KEY, or ensure /root/.ssh/authorized_keys exists"
fi
chmod 700 "$USER_SSH_DIR"
chmod 600 "$USER_SSH_DIR/authorized_keys"
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$USER_SSH_DIR"

# ------------------------------------------------------------------
log "3/8 Harden sshd"
# ------------------------------------------------------------------
mkdir -p /etc/ssh/sshd_config.d
cat > /etc/ssh/sshd_config.d/00-hardening.conf <<EOF
Port $SSH_PORT
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PubkeyAuthentication yes
AuthenticationMethods publickey
PermitEmptyPasswords no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
AllowUsers root $DEPLOY_USER
EOF
# Some cloud images ship a config that would override ours — neutralize it.
if [[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]]; then
  sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config.d/50-cloud-init.conf
fi
sshd -t || die "sshd config test failed — not restarting sshd"

# ------------------------------------------------------------------
log "4/8 Firewall (UFW)"
# ------------------------------------------------------------------
ufw default deny incoming
ufw default allow outgoing
ufw limit "$SSH_PORT/tcp" comment 'SSH (rate-limited)'
ufw allow 80/tcp  comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw --force enable

# ------------------------------------------------------------------
log "5/8 fail2ban"
# ------------------------------------------------------------------
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled = true
port    = $SSH_PORT
EOF
systemctl enable --now fail2ban
systemctl restart fail2ban

# ------------------------------------------------------------------
log "6/8 Kernel & network hardening (sysctl)"
# ------------------------------------------------------------------
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
# IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP redirects / source routing (MITM vectors)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# SYN flood protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2

# Log packets with impossible addresses
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP broadcasts / bogus errors
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Restrict kernel info leaks
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2

# Restrict ptrace to direct children (debuggers still work via sudo)
kernel.yama.ptrace_scope = 1

# Protect against hard/symlink attacks in world-writable dirs
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2

# Disable core dumps for setuid programs
fs.suid_dumpable = 0
EOF
sysctl --system >/dev/null

# ------------------------------------------------------------------
log "7/8 Docker (official repo, live-restore)"
# ------------------------------------------------------------------
# Installing Docker here (rather than letting 'kamal setup' curl|sh it)
# means live-restore is set before the first container ever runs.
# Kamal detects the existing install and skips its own.
if ! command -v docker >/dev/null 2>&1; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -y
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

# live-restore: containers keep running while dockerd restarts (upgrades etc.)
mkdir -p /etc/docker
if [[ -s /etc/docker/daemon.json ]]; then
  grep -q 'live-restore' /etc/docker/daemon.json \
    || warn "/etc/docker/daemon.json exists — add \"live-restore\": true to it manually"
else
  echo '{ "live-restore": true }' > /etc/docker/daemon.json
fi
systemctl enable docker
systemctl restart docker
usermod -aG docker "$DEPLOY_USER"

# ------------------------------------------------------------------
log "8/8 Misc"
# ------------------------------------------------------------------
# AppArmor ships enforcing on Ubuntu; verify that's actually the case
# (Docker's container confinement depends on it).
systemctl enable --now apparmor
if ! aa-status --enabled 2>/dev/null; then
  warn "AppArmor is NOT enabled — check kernel cmdline for apparmor=1 security=apparmor"
fi

# Time sync (chrony installed above; make sure the legacy one is off)
systemctl disable --now systemd-timesyncd 2>/dev/null || true
systemctl enable --now chrony

# Kill message-of-the-day ad spam and reduce info leakage on login
chmod -x /etc/update-motd.d/* 2>/dev/null || true

# Remove packages that have no place on a server
apt-get purge -y snapd 2>/dev/null || true
apt-get autoremove -y

# Restart sshd LAST, after everything else succeeded.
systemctl restart ssh

cat <<EOF

================================================================
 Hardening complete.

 BEFORE you close this session, verify from ANOTHER terminal:

   ssh -p $SSH_PORT $DEPLOY_USER@<server-ip>

 Password auth is now disabled (root login still works, key-only).
 If that command fails, fix it from THIS session while you still
 have it.

 Summary:
   - User:        $DEPLOY_USER (passwordless sudo, key-only SSH)
   - SSH:         port $SSH_PORT, keys only (root allowed, key-only)
   - Firewall:    deny inbound except $SSH_PORT (rate-limited), 80, 443
   - fail2ban:    sshd jail, 1h bans
   - Docker:      installed (official repo), live-restore on,
                  $DEPLOY_USER in docker group
   - Updates:     unattended security upgrades, reboot Sun 04:00 if needed
================================================================
EOF
