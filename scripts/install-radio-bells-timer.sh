#!/usr/bin/env bash
set -euo pipefail

project_root="${1:-$(pwd)}"
service_user="${SUDO_USER:-$USER}"
if [[ ! -x "$project_root/.venv/bin/flask" || ! -f "$project_root/run.py" || ! -f "$project_root/.env" ]]; then
  echo "Brak .venv/bin/flask, run.py lub .env w: $project_root" >&2
  exit 1
fi

sudo tee /etc/systemd/system/sp2-radio-bells.service >/dev/null <<EOF
[Unit]
Description=SP2 ADMIN - automatyczny dzwonek radiowezla
After=network-online.target sp2-admin.service

[Service]
Type=oneshot
User=$service_user
WorkingDirectory=$project_root
EnvironmentFile=$project_root/.env
ExecStart=$project_root/.venv/bin/flask --app run.py radio-bells-tick
EOF

sudo tee /etc/systemd/system/sp2-radio-bells.timer >/dev/null <<'EOF'
[Unit]
Description=SP2 ADMIN - sprawdzanie dzwonkow co minute

[Timer]
OnCalendar=*-*-* *:*:00
AccuracySec=1s
Persistent=false
Unit=sp2-radio-bells.service

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now sp2-radio-bells.timer
systemctl status sp2-radio-bells.timer --no-pager
