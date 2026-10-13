#!/usr/bin/env bash
set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
ENV_FILE="$ROOT/.env"
SERVICE="sp2-admin.service"

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Brak pliku $ENV_FILE"
  exit 1
fi

STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="$ENV_FILE.backup-$STAMP"
cp -a "$ENV_FILE" "$BACKUP"
echo "Backup: $BACKUP"

python3 - "$ENV_FILE" "$ROOT" <<'PY'
from pathlib import Path
import secrets
import sys

path = Path(sys.argv[1])
root = Path(sys.argv[2])

existing = {}
for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    k, v = line.split("=", 1)
    existing[k.strip()] = v.strip()

def keep(name, default=""):
    value = existing.get(name, "")
    return value if value != "" else default

secret_key = keep("SECRET_KEY")
api_token = keep("SP2_API_TOKEN", keep("AGENT_API_TOKEN"))
if not secret_key:
    secret_key = secrets.token_urlsafe(48)
if not api_token:
    api_token = secrets.token_urlsafe(48)

enrollment = keep("AGENT_ENROLLMENT_TOKEN") or secrets.token_urlsafe(48)

values = {
    "FLASK_ENV": "production",
    "SECRET_KEY": secret_key,
    "APP_NAME": keep("APP_NAME", "SP2 ADMIN"),
    "APP_VERSION": keep("APP_VERSION", "7.1.0-dev.1"),
    "APP_AUTHOR": keep("APP_AUTHOR", "Mariusz Klejno"),
    "LOG_LEVEL": keep("LOG_LEVEL", "INFO"),
    "DATABASE_URI": keep("DATABASE_URI", f"sqlite:///{root / 'instance' / 'sp2-admin.sqlite3'}"),
    "SNAPSHOT_DIR": keep("SNAPSHOT_DIR", "/srv/sp2-admin/monitoring-snapshots"),
    "SESSION_COOKIE_SECURE": keep("SESSION_COOKIE_SECURE", "false"),
    "SP2_API_TOKEN": api_token,
    "SP2_API_TOKEN_PREVIOUS": keep("SP2_API_TOKEN_PREVIOUS", ""),
    "AGENT_ENROLLMENT_TOKEN": enrollment,
    "AGENT_OFFLINE_AFTER_SECONDS": keep("AGENT_OFFLINE_AFTER_SECONDS", "180"),
    "LDAP_URI": keep("LDAP_URI", "ldap://192.168.0.143"),
    "LDAP_BIND_DN": keep("LDAP_BIND_DN", ""),
    "LDAP_BIND_PASSWORD": keep("LDAP_BIND_PASSWORD", ""),
    "LDAP_BASE_DN": keep("LDAP_BASE_DN", "DC=sp2,DC=lan"),
    "LDAP_USE_SSL": keep("LDAP_USE_SSL", "false"),
    "LDAP_CONNECT_TIMEOUT": keep("LDAP_CONNECT_TIMEOUT", "5"),
    "LDAP_RECEIVE_TIMEOUT": keep("LDAP_RECEIVE_TIMEOUT", "15"),
    "LDAP_PAGE_SIZE": keep("LDAP_PAGE_SIZE", "500"),
    "LDAP_WRITE_BIND_DN": keep("LDAP_WRITE_BIND_DN", ""),
    "LDAP_WRITE_BIND_PASSWORD": keep("LDAP_WRITE_BIND_PASSWORD", ""),
    "AD_DOMAIN_FQDN": keep("AD_DOMAIN_FQDN", "sp2.lan"),
    "AD_DOMAIN_NETBIOS": keep("AD_DOMAIN_NETBIOS", "SP2"),
    "AD_DNS_SERVERS": keep("AD_DNS_SERVERS", "192.168.0.143"),
    "AD_JOIN_ALLOWED_OU_BASES": keep("AD_JOIN_ALLOWED_OU_BASES", "OU=Komputery,DC=sp2,DC=lan"),
    "AD_TEACHER_USER_OU": keep("AD_TEACHER_USER_OU", "OU=Nauczyciele,OU=Uzytkownicy,DC=sp2,DC=lan"),
    "AD_TEACHER_COMPUTER_OU": keep("AD_TEACHER_COMPUTER_OU", "OU=Nauczyciele,OU=Komputery,DC=sp2,DC=lan"),
    "AD_PASSWORD_MIN_LENGTH": keep("AD_PASSWORD_MIN_LENGTH", "12"),
    "WEB_FILTER_ENFORCEMENT_ENABLED": keep("WEB_FILTER_ENFORCEMENT_ENABLED", "false"),
    "RADIO_PLAYBACK_ENABLED": keep("RADIO_PLAYBACK_ENABLED", "false"),
    "MONITORING_STREAMS_ENABLED": keep("MONITORING_STREAMS_ENABLED", "false"),
}

sections = [
    ("SP2 ADMIN", ["FLASK_ENV", "SECRET_KEY", "APP_NAME", "APP_VERSION", "APP_AUTHOR", "LOG_LEVEL", "DATABASE_URI", "SNAPSHOT_DIR", "SESSION_COOKIE_SECURE"]),
    ("AGENT WINDOWS", ["SP2_API_TOKEN", "SP2_API_TOKEN_PREVIOUS", "AGENT_ENROLLMENT_TOKEN", "AGENT_OFFLINE_AFTER_SECONDS"]),
    ("LDAP / SAMBA AD", ["LDAP_URI", "LDAP_BIND_DN", "LDAP_BIND_PASSWORD", "LDAP_BASE_DN", "LDAP_USE_SSL", "LDAP_CONNECT_TIMEOUT", "LDAP_RECEIVE_TIMEOUT", "LDAP_PAGE_SIZE", "LDAP_WRITE_BIND_DN", "LDAP_WRITE_BIND_PASSWORD"]),
    ("DOMENA", ["AD_DOMAIN_FQDN", "AD_DOMAIN_NETBIOS", "AD_DNS_SERVERS", "AD_JOIN_ALLOWED_OU_BASES", "AD_TEACHER_USER_OU", "AD_TEACHER_COMPUTER_OU", "AD_PASSWORD_MIN_LENGTH"]),
    ("USLUGI SZKOLNE", ["WEB_FILTER_ENFORCEMENT_ENABLED", "RADIO_PLAYBACK_ENABLED", "MONITORING_STREAMS_ENABLED"]),
]

out = []
out.append("############################################################")
out.append("# SP2 ADMIN - plik wygenerowany automatycznie")
out.append("############################################################")
out.append("")
for title, keys in sections:
    out.append("############################################################")
    out.append(f"# {title}")
    out.append("############################################################")
    for key in keys:
        out.append(f"{key}={values[key]}")
    out.append("")

path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")

print(".env zaktualizowany")
print("SECRET_KEY: zachowany" if existing.get("SECRET_KEY") else "SECRET_KEY: wygenerowany")
print("SP2_API_TOKEN: zachowany" if existing.get("SP2_API_TOKEN") or existing.get("AGENT_API_TOKEN") else "SP2_API_TOKEN: wygenerowany")
print("AGENT_ENROLLMENT_TOKEN: zachowany" if existing.get("AGENT_ENROLLMENT_TOKEN") else "AGENT_ENROLLMENT_TOKEN: wygenerowany")
PY

chmod 600 "$ENV_FILE"

if [[ -x "$ROOT/.venv/bin/python" ]]; then
  PY="$ROOT/.venv/bin/python"
elif [[ -x "$ROOT/venv/bin/python" ]]; then
  PY="$ROOT/venv/bin/python"
else
  PY="python3"
fi

"$PY" - <<PY
from dotenv import load_dotenv
from pathlib import Path
p = Path(r"$ENV_FILE")
assert load_dotenv(p, override=True)
print("Test .env: OK")
PY

sudo systemctl restart "$SERVICE"
sudo systemctl is-active --quiet "$SERVICE"
echo "$SERVICE: active"

echo "Gotowe. Sekrety nie zostały wypisane na ekran."