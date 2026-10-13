#!/usr/bin/env bash
set -euo pipefail

SUDOERS_FILE="/etc/sudoers.d/sp2-admin-agent-profile"
HELPER="/usr/local/sbin/sp2-agent-profile-assign"
PANEL_USER="${SP2_ADMIN_USER:-${SUDO_USER:-baraqda}}"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Uruchom przez sudo." >&2
  exit 1
fi

cat > "$HELPER" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

HOST="${1:-}"
PROFILE="${2:-}"

if [[ -z "$HOST" || ! "$HOST" =~ ^[A-Za-z0-9_-]{1,63}$ ]]; then
  echo "Nieprawidlowa nazwa komputera." >&2
  exit 2
fi

case "$PROFILE" in
  Sala11) TARGET_OU='OU=Sala11,OU=Komputery,DC=sp2,DC=lan' ;;
  Sala32) TARGET_OU='OU=Sala32,OU=Komputery,DC=sp2,DC=lan' ;;
  Sala4) TARGET_OU='OU=Sala4,OU=Komputery,DC=sp2,DC=lan' ;;
  Sala7) TARGET_OU='OU=Sala7,OU=Komputery,DC=sp2,DC=lan' ;;
  Nauczyciel) TARGET_OU='OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan' ;;
  Administracja) TARGET_OU='OU=Administracja,OU=Komputery,DC=sp2,DC=lan' ;;
  *) echo "Nieprawidlowy profil." >&2; exit 2 ;;
esac

ACCOUNT="${HOST^^}$"
if ! samba-tool computer show "$ACCOUNT" >/dev/null 2>&1; then
  echo "Obiekt komputera $ACCOUNT nie istnieje jeszcze w Samba AD." >&2
  exit 3
fi

CURRENT_DN="$(samba-tool computer show "$ACCOUNT" 2>/dev/null | sed -n 's/^distinguishedName:[[:space:]]*//p' | head -n1)"
if [[ "$CURRENT_DN" == *",$TARGET_OU" ]]; then
  echo "$ACCOUNT jest juz w $TARGET_OU"
  exit 0
fi

samba-tool computer move "$ACCOUNT" "$TARGET_OU"
echo "$ACCOUNT -> $TARGET_OU"
EOF
chmod 0755 "$HELPER"

cat > "$SUDOERS_FILE" <<EOF
# SP2 ADMIN - ograniczone przypisywanie profilu instalacyjnego komputera.
$PANEL_USER ALL=(root) NOPASSWD: $HELPER
EOF
chmod 0440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE" >/dev/null

echo "Profile helper: $HELPER"
echo "Sudoers: $SUDOERS_FILE"
echo "Panel user: $PANEL_USER"
