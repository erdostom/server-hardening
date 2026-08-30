# Ubuntu server hardening scripts

Bash scripts that harden Ubuntu servers (22.04 / 24.04), tuned for hosts
that will run Rails apps deployed with [Kamal](https://kamal-deploy.org),
but generic enough for any Ubuntu box. Served via GitHub Pages at
`hardening.bithaiku.com`, so each can run as a one-liner.

## The scripts

| Script | For | One-liner |
|---|---|---|
| [`harden-server.sh`](harden-server.sh) | A **freshly provisioned** server | `curl -fsSL https://hardening.bithaiku.com/harden-server.sh \| sudo bash` |
| [`harden-existing-server.sh`](harden-existing-server.sh) | A server **already running apps** | `curl -fsSL https://hardening.bithaiku.com/harden-existing-server.sh \| sudo bash` |
| [`auto-updates.sh`](auto-updates.sh) | Any box: **only** automatic updates + weekly reboot | `curl -fsSL https://hardening.bithaiku.com/auto-updates.sh \| sudo bash` |

Prefer to read before running? Same URLs, two steps:

```sh
curl -fsSL https://hardening.bithaiku.com/harden-server.sh -o harden-server.sh
less harden-server.sh
sudo bash harden-server.sh
```

> Pipe to `bash`, not `sh` — the scripts use bash features, and `sh` is
> dash on Ubuntu.

## What they do

### `harden-server.sh` — fresh box

1. Full system update + unattended security upgrades
2. Creates a non-root sudo user (`deploy`) with your SSH key
3. Hardens sshd: key-only auth, root allowed but key-only
   (`prohibit-password`), `AllowUsers root deploy`, tight limits
4. UFW: deny inbound except rate-limited SSH, 80, 443
5. fail2ban (sshd jail, 1 h bans)
6. Kernel/network sysctl hardening (spoofing, redirects, SYN floods,
   info-leak restrictions, eBPF/ptrace limits)
7. Docker from the official apt repo with `live-restore: true` set
   **before** the first container ever runs; `deploy` joins the
   `docker` group
8. AppArmor verified enforcing, chrony time sync, motd noise and
   snapd removed

Reboots happen **only on Sundays at 04:00, and only if an update
requires one** (`/etc/cron.d/reboot-if-required`).

### `harden-existing-server.sh` — production box

Same baseline, minus everything that could take down running apps:

- No blanket `apt upgrade` — pending security updates are reported so
  you can apply them in a maintenance window
- **UFW is additive only**: existing rules and default policies are
  never reset. If UFW is inactive, the script shows what's listening
  and asks before enabling (the prompt reads `/dev/tty`, so it works
  through `curl | bash` too)
- No `AllowUsers` — existing accounts keep SSH access; users with a
  password but no key are named in a warning before password auth is
  disabled
- snapd kept (certbot is often a snap); eBPF sysctl restrictions
  opt-in via `HARDEN_BPF=yes` (they break some observability agents)
- Docker `live-restore` enabled as the **last** step: a daemon reload
  is tried first (no container impact); only if that fails does it
  fall back to a full dockerd restart, after a 5-second Ctrl-C-able
  warning

### `auto-updates.sh` — updates only

Unattended security upgrades (daily) plus the Sunday-if-required
reboot cron. Touches nothing else — no firewall, ssh, users, or
sysctl.

## Configuration

Settings are env vars with sane defaults, so they pass straight
through `sudo`:

```sh
curl -fsSL https://hardening.bithaiku.com/harden-server.sh | \
  sudo DEPLOY_USER=app SSH_PORT=2222 SSH_PUBLIC_KEY="ssh-ed25519 AAAA…" bash
```

| Variable | Default | Scripts | Meaning |
|---|---|---|---|
| `DEPLOY_USER` | `deploy` | both harden | Sudo + docker user to create |
| `SSH_PORT` | `22` | both harden | sshd port (UFW + fail2ban follow it) |
| `SSH_PUBLIC_KEY` | *(root's keys)* | both harden | Key for the deploy user; falls back to `/root/.ssh/authorized_keys` |
| `HARDEN_BPF` | `no` | existing | Also apply eBPF sysctl restrictions |
| `REBOOT_CRON` | `0 4 * * 0` | auto-updates | When to check for a required reboot |

## How to read the scripts

Each script is a straight line, top to bottom:

- **Header comment** — what it does and how to run it.
- **Configuration block** — the env vars above.
- **`main()`** — numbered step sections (`1/8 …`), each introduced by a
  `log` banner. The whole body is a function invoked only on the last
  line (`main "$@"`), so a partially downloaded script parses to
  nothing and executes nothing — this is what makes `curl | bash`
  safe against truncation.
- **Ordering is deliberate**: sshd's config is validated (`sshd -t`)
  when written but sshd restarts near the end, after everything else
  succeeded; in the existing-server variant the dockerd
  restart-risking step comes dead last, so aborting it loses nothing.

## After running

The final banner says it too: **before closing your session**, confirm
from a second terminal that `ssh -p <port> deploy@server` works.
Password auth is disabled at that point; your current session is your
recovery path if a key went missing.

## Kamal notes

- Docker is preinstalled with `live-restore`, so `kamal setup` detects
  it and skips its own `curl | sh` install.
- Kamal's default of SSHing as root works (root remains key-only), or
  set `ssh: { user: deploy }` — the deploy user is in the `docker`
  group.
- **Docker punches through UFW**: any port published with `-p` is
  internet-reachable regardless of firewall rules. Bind accessory
  ports (postgres, redis) to `127.0.0.1` in `deploy.yml`.
- No container log rotation is configured; if disk becomes a concern,
  set `logging:` options per app in `deploy.yml`.

## Hosting setup (GitHub Pages)

`hardening.bithaiku.com` is this repo served by GitHub Pages with a
custom domain (`CNAME` file + a DNS CNAME record pointing at
`<user>.github.io`). Files map 1:1 to URLs, so publishing a change is
just a push. An empty `.nojekyll` file keeps Pages from running the
files through Jekyll.
