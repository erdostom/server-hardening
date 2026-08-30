#!/usr/bin/env bash
#
# auto-updates.sh — just automatic security updates + weekly reboot.
#
# Sets up on Ubuntu:
#   - unattended-upgrades applying security patches daily
#   - a reboot on Sundays at 04:00, only if an update requires one
#
# Touches nothing else (no firewall, ssh, users, sysctl).
#
# Run as root: sudo bash auto-updates.sh
# or straight from the web (must be bash, not sh — and pipe to sudo):
#   curl -fsSL https://hardening.bithaiku.com/auto-updates.sh | sudo bash
#   curl -fsSL https://hardening.bithaiku.com/auto-updates.sh | sudo REBOOT_CRON="0 5 * * 6" bash
# The whole script is wrapped in main() called on the last line, so a
# partially downloaded script executes nothing.

set -euo pipefail

# When to reboot if /var/run/reboot-required exists (cron format).
REBOOT_CRON="${REBOOT_CRON:-0 4 * * 0}"   # Sundays 04:00

log()  { echo -e "\n\033[1;32m==> $*\033[0m"; }
warn() { echo -e "\033[1;33m[!] $*\033[0m"; }
die()  { echo -e "\033[1;31m[x] $*\033[0m" >&2; exit 1; }

main() {

[[ $EUID -eq 0 ]] || die "Run as root: sudo bash auto-updates.sh (or curl ... | sudo bash)"
. /etc/os-release
[[ ${ID:-} == "ubuntu" ]] || die "This script targets Ubuntu (detected: ${ID:-unknown})"

export DEBIAN_FRONTEND=noninteractive

log "Installing unattended-upgrades"
apt-get update -y
apt-get install -y unattended-upgrades apt-listchanges

log "Configuring security-only unattended upgrades"
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

log "Scheduling weekly reboot check ($REBOOT_CRON)"
cat > /etc/cron.d/reboot-if-required <<EOF
$REBOOT_CRON root [ -f /var/run/reboot-required ] && /sbin/shutdown -r +1 "Rebooting for pending security updates"
EOF
chmod 644 /etc/cron.d/reboot-if-required

cat <<EOF

================================================================
 Done.
   - Security updates: applied automatically, daily
   - Reboot:           '$REBOOT_CRON' (cron), only when required
                       (checks /var/run/reboot-required)

 Test the upgrade config with:  unattended-upgrade --dry-run --debug
================================================================
EOF

}

main "$@"
