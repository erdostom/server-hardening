#!/usr/bin/env bash
#
# harden-existing.sh — hardening for an Ubuntu server ALREADY running apps.
#
# Production-safe variant of harden.sh:
#   - No blanket `apt upgrade` (only installs the tools it needs; ongoing
#     security patches handled by unattended-upgrades)
#   - Honors existing UFW rules: never resets, never changes default
#     policies on an already-active firewall, only ADDS allow rules.
#     If UFW is inactive, shows what's listening and asks before enabling.
#   - No `AllowUsers` restriction (won't lock out existing accounts)
#   - Refuses to disable password auth unless it finds an SSH key
#   - Does NOT purge snapd (certbot is often installed via snap)
#   - eBPF sysctl restrictions off by default (can break observability
#     agents like Datadog system-probe, Cilium, bcc tools)
#
# Run as root: sudo bash harden-existing.sh
#
# Still verify from a second terminal that SSH works before logging out.

set -euo pipefail

# ------------------------------------------------------------------
# Configuration — edit before running
# ------------------------------------------------------------------
DEPLOY_USER="${DEPLOY_USER:-deploy}"
SSH_PORT="${SSH_PORT:-22}"
# Public key for the deploy user. If empty, root's authorized_keys is copied.
SSH_PUBLIC_KEY="${SSH_PUBLIC_KEY:-}"
# Set to "yes" to also apply the eBPF restrictions (see note above).
HARDEN_BPF="${HARDEN_BPF:-no}"
# ------------------------------------------------------------------

log()  { echo -e "\n\033[1;32m==> $*\033[0m"; }
warn() { echo -e "\033[1;33m[!] $*\033[0m"; }
die()  { echo -e "\033[1;31m[x] $*\033[0m" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"
. /etc/os-release
[[ ${ID:-} == "ubuntu" ]] || die "This script targets Ubuntu (detected: ${ID:-unknown})"

export DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------------
log "1/7 Install tooling + configure security updates (no full upgrade)"
# ------------------------------------------------------------------
apt-get update -y
apt-get install -y \
  unattended-upgrades apt-listchanges \
  ufw fail2ban \
  curl ca-certificates gnupg \
  chrony

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
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades

# Reboot only on Sundays 04:00, and only if an update requires it.
cat > /etc/cron.d/reboot-if-required <<'EOF'
0 4 * * 0 root [ -f /var/run/reboot-required ] && /sbin/shutdown -r +1 "Rebooting for pending security updates"
EOF
chmod 644 /etc/cron.d/reboot-if-required

if apt-get -s upgrade | grep -q '^Inst.*-security'; then
  warn "Pending security updates exist. Apply them in a maintenance window:"
  warn "  sudo unattended-upgrade   (services may restart, incl. Docker)"
fi

# ------------------------------------------------------------------
log "2/7 Create user '$DEPLOY_USER' (skipped if it exists)"
# ------------------------------------------------------------------
if ! id -u "$DEPLOY_USER" >/dev/null 2>&1; then
  adduser --disabled-password --gecos "" "$DEPLOY_USER"
fi
usermod -aG sudo "$DEPLOY_USER"
echo "$DEPLOY_USER ALL=(ALL) NOPASSWD:ALL" > "/etc/sudoers.d/90-$DEPLOY_USER"
chmod 440 "/etc/sudoers.d/90-$DEPLOY_USER"

USER_SSH_DIR="/home/$DEPLOY_USER/.ssh"
mkdir -p "$USER_SSH_DIR"
if [[ -n "$SSH_PUBLIC_KEY" ]]; then
  grep -qxF "$SSH_PUBLIC_KEY" "$USER_SSH_DIR/authorized_keys" 2>/dev/null \
    || echo "$SSH_PUBLIC_KEY" >> "$USER_SSH_DIR/authorized_keys"
elif [[ ! -s "$USER_SSH_DIR/authorized_keys" && -s /root/.ssh/authorized_keys ]]; then
  cp /root/.ssh/authorized_keys "$USER_SSH_DIR/authorized_keys"
fi
[[ -s "$USER_SSH_DIR/authorized_keys" ]] \
  || die "No SSH key for $DEPLOY_USER: set SSH_PUBLIC_KEY or populate /root/.ssh/authorized_keys"
chmod 700 "$USER_SSH_DIR"
chmod 600 "$USER_SSH_DIR/authorized_keys"
chown -R "$DEPLOY_USER:$DEPLOY_USER" "$USER_SSH_DIR"

# ------------------------------------------------------------------
log "3/7 Harden sshd"
# ------------------------------------------------------------------
# Warn about existing users who could currently log in but have no key —
# they lose SSH access once password auth is off.
while IFS=: read -r user _ uid _ _ home shell; do
  [[ $uid -ge 1000 || $user == root ]] || continue
  [[ $shell == */nologin || $shell == */false ]] && continue
  [[ -s "$home/.ssh/authorized_keys" ]] && continue
  passwd -S "$user" 2>/dev/null | awk '$2 == "P"' | grep -q . \
    && warn "User '$user' has a password but no SSH key — will lose SSH access"
done < /etc/passwd

# No AllowUsers here: existing accounts keep their access (key-only).
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
MaxAuthTries 3
LoginGraceTime 20
ClientAliveInterval 300
ClientAliveCountMax 2
EOF
if [[ -f /etc/ssh/sshd_config.d/50-cloud-init.conf ]]; then
  sed -i 's/^PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config.d/50-cloud-init.conf
fi
sshd -t || die "sshd config test failed — not restarting sshd"

# ------------------------------------------------------------------
log "4/7 Firewall (UFW) — additive only, existing rules untouched"
# ------------------------------------------------------------------
# `ufw allow`/`ufw limit` only add rules; nothing here deletes or resets.
ufw limit "$SSH_PORT/tcp" comment 'SSH (rate-limited)'
ufw allow 80/tcp  comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

if ufw status | grep -q "Status: active"; then
  log "UFW already active — default policies and existing rules left as-is"
else
  warn "UFW is installed but INACTIVE. Currently listening (non-loopback):"
  ss -tlnpu | grep -vE '127\.0\.0\.1|\[::1\]' | sed 's/^/    /'
  warn "Only $SSH_PORT, 80, 443 are allowed. Anything else above needs a"
  warn "'ufw allow' rule BEFORE enabling, or it becomes unreachable."
  warn "(Docker-published container ports bypass UFW and keep working.)"
  if [[ -t 0 ]]; then
    read -r -p "Set default-deny and enable UFW now? [y/N] " reply
    if [[ $reply =~ ^[Yy]$ ]]; then
      ufw default deny incoming
      ufw default allow outgoing
      ufw --force enable
    else
      warn "UFW left disabled. Enable later with: ufw default deny incoming && ufw enable"
    fi
  else
    warn "Non-interactive session — UFW left disabled. Review and enable manually."
  fi
fi

# ------------------------------------------------------------------
log "5/7 fail2ban"
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
log "6/7 Kernel & network hardening (sysctl)"
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
if [[ $HARDEN_BPF == "yes" ]]; then
  cat >> /etc/sysctl.d/99-hardening.conf <<'EOF'

# eBPF restrictions — breaks eBPF-based observability agents
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
EOF
else
  warn "eBPF sysctl restrictions skipped (set HARDEN_BPF=yes to enable)"
fi
sysctl --system >/dev/null

# ------------------------------------------------------------------
log "7/7 Misc"
# ------------------------------------------------------------------
systemctl disable --now systemd-timesyncd 2>/dev/null || true
systemctl enable --now chrony
chmod -x /etc/update-motd.d/* 2>/dev/null || true
# NOTE: snapd intentionally NOT removed (certbot is often a snap).

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
   - Firewall:    existing UFW rules honored; added $SSH_PORT, 80, 443
   - fail2ban:    sshd jail, 1h bans
   - Updates:     unattended security upgrades, reboot Sun 04:00 if needed
   - Pending upgrades: run 'unattended-upgrade' in a maintenance window
================================================================
EOF
