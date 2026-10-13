#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYNC_SOURCE="$SOURCE_DIR/sync-agent-deployment-groups.py"
INSTALL_DIR="/usr/local/lib/sp2-admin"
SYNC_TARGET="$INSTALL_DIR/sync-agent-deployment-groups.py"
SERVICE_FILE="/etc/systemd/system/sp2-agent-group-sync.service"
TIMER_FILE="/etc/systemd/system/sp2-agent-group-sync.timer"
SUDOERS_FILE="/etc/sudoers.d/sp2-admin-agent-group-sync"
STATE_DIR="/etc/sp2-admin"
STATE_FILE="$STATE_DIR/agent-deployment-rooms.conf"
GROUP_HELPER="/usr/local/sbin/sp2-agent-group-members"
ROOM_HELPER="/usr/local/sbin/sp2-agent-room-computers"
LOG_HELPER="/usr/local/sbin/sp2-agent-group-sync-log"
TOGGLE_HELPER="/usr/local/sbin/sp2-agent-room-toggle"
PANEL_USER="${SP2_ADMIN_USER:-${SUDO_USER:-baraqda}}"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Uruchom przez sudo." >&2
  exit 1
fi

if [[ ! -f "$SYNC_SOURCE" ]]; then
  echo "Brak pliku: $SYNC_SOURCE" >&2
  exit 1
fi

install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$SYNC_SOURCE" "$SYNC_TARGET"
install -d -m 0755 "$STATE_DIR"
if [[ ! -f "$STATE_FILE" ]]; then
  cat > "$STATE_FILE" <<'EOF'
Sala11=enabled
Sala32=enabled
Sala4=enabled
Sala7=enabled
EOF
fi
chmod 0644 "$STATE_FILE"

cat > "$SERVICE_FILE" <<'EOF'
[Unit]
Description=SP2 ADMIN - synchronizacja grup wdrozeniowych agentow z OU
After=samba-ad-dc.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /usr/local/lib/sp2-admin/sync-agent-deployment-groups.py --prune
User=root
Group=root
Nice=10
EOF

cat > "$TIMER_FILE" <<'EOF'
[Unit]
Description=SP2 ADMIN - cykliczna synchronizacja grup wdrozeniowych agentow

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true
Unit=sp2-agent-group-sync.service

[Install]
WantedBy=timers.target
EOF

cat > "$GROUP_HELPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
GROUP="${1:-}"
if [[ -z "$GROUP" || ! "$GROUP" =~ ^SP2-Agent-[A-Za-z0-9_-]+$ ]]; then
  echo "Nieprawidlowa nazwa grupy." >&2
  exit 2
fi
exec samba-tool group listmembers "$GROUP"
EOF
chmod 0755 "$GROUP_HELPER"

cat > "$ROOM_HELPER" <<'EOF'
#!/usr/bin/env python3
from __future__ import annotations
import sys
import ldb
from samba.auth import system_session
from samba.param import LoadParm
from samba.samdb import SamDB

ROOMS = {"Sala11", "Sala32", "Sala4", "Sala7"}
room = sys.argv[1] if len(sys.argv) > 1 else ""
if room not in ROOMS:
    print("Nieprawidlowa sala.", file=sys.stderr)
    raise SystemExit(2)
lp = LoadParm()
lp.load_default()
samdb = SamDB(url=lp.private_path("sam.ldb"), session_info=system_session(), lp=lp)
base = f"OU={room},OU=Komputery,DC=sp2,DC=lan"
rows = samdb.search(base=base, scope=ldb.SCOPE_SUBTREE, expression="(objectClass=computer)", attrs=["sAMAccountName"])
items = sorted({str(row["sAMAccountName"][0]).strip() for row in rows if "sAMAccountName" in row}, key=str.casefold)
for item in items:
    if item:
        print(item)
EOF
chmod 0755 "$ROOM_HELPER"

cat > "$LOG_HELPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec journalctl -u sp2-agent-group-sync.service -n 80 --no-pager --output=short-iso
EOF
chmod 0755 "$LOG_HELPER"

cat > "$TOGGLE_HELPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
ROOM="${1:-}"
ACTION="${2:-}"
STATE_FILE="/etc/sp2-admin/agent-deployment-rooms.conf"
case "$ROOM" in Sala11|Sala32|Sala4|Sala7) ;; *) echo "Nieprawidlowa sala." >&2; exit 2 ;; esac
case "$ACTION" in enable) VALUE=enabled ;; disable) VALUE=disabled ;; *) echo "Uzyj enable albo disable." >&2; exit 2 ;; esac
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
awk -F= -v room="$ROOM" '$1 != room {print}' "$STATE_FILE" > "$TMP" || true
printf '%s=%s\n' "$ROOM" "$VALUE" >> "$TMP"
install -m 0644 "$TMP" "$STATE_FILE"
systemctl start sp2-agent-group-sync.service
EOF
chmod 0755 "$TOGGLE_HELPER"

SYSTEMCTL="$(command -v systemctl)"

cat > "$SUDOERS_FILE" <<EOF
# SP2 ADMIN - minimalne uprawnienia panelu do modulu Wdrozenie agentow.
$PANEL_USER ALL=(root) NOPASSWD: $SYSTEMCTL start sp2-agent-group-sync.service
$PANEL_USER ALL=(root) NOPASSWD: $GROUP_HELPER
$PANEL_USER ALL=(root) NOPASSWD: $ROOM_HELPER
$PANEL_USER ALL=(root) NOPASSWD: $LOG_HELPER
$PANEL_USER ALL=(root) NOPASSWD: $TOGGLE_HELPER
EOF
chmod 0440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE" >/dev/null

systemctl daemon-reload
systemctl enable --now sp2-agent-group-sync.timer
systemctl start sp2-agent-group-sync.service

echo "sp2-agent-group-sync.timer: $(systemctl is-active sp2-agent-group-sync.timer)"
echo "sp2-agent-group-sync.service: $(systemctl is-active sp2-agent-group-sync.service 2>/dev/null || true)"
echo "Panel user: $PANEL_USER"
echo "Sudoers: $SUDOERS_FILE"
echo "Room state: $STATE_FILE"
systemctl list-timers sp2-agent-group-sync.timer --no-pager
