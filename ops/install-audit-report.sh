#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
    echo "Uruchom instalator przez sudo." >&2
    exit 1
fi

source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
app_dir="${1:-/home/baraqda/sp2-admin-6.0.0-commit-0003}"
app_dir="$(realpath -- "${app_dir}")"
report_dir="/var/lib/sp2-admin-audit"

id codex-audit >/dev/null 2>&1 || {
    echo "Brak konta codex-audit." >&2
    exit 1
}

test -x "${app_dir}/.venv/bin/python" || {
    echo "Brak interpretera aplikacji: ${app_dir}/.venv/bin/python" >&2
    exit 1
}

test -f "${app_dir}/.env" || {
    echo "Brak produkcyjnego pliku .env." >&2
    exit 1
}

test -d "${app_dir}/instance" || {
    echo "Brak produkcyjnego katalogu instance." >&2
    exit 1
}

runuser -u codex-audit -- test -x "${app_dir}/.venv/bin/python" || {
    echo "Konto codex-audit nie może uruchomić interpretera aplikacji." >&2
    exit 1
}

runuser -u codex-audit -- test -r "${app_dir}/app/__init__.py" || {
    echo "Konto codex-audit nie może odczytać kodu testowanej aplikacji." >&2
    exit 1
}

if runuser -u codex-audit -- test -r "${app_dir}/.env"; then
    echo "Konto codex-audit nie może mieć bezpośredniego dostępu do .env." >&2
    exit 1
fi

install -d -o root -g root -m 0755 /usr/local/lib/sp2-admin
install -o root -g root -m 0755 \
    "${source_dir}/sp2_audit_report.py" \
    /usr/local/lib/sp2-admin/sp2_audit_report.py

install -d -o root -g codex-audit -m 0770 "${report_dir}"
install -d -o root -g root -m 0555 "${report_dir}/empty-instance"
touch "${report_dir}/empty.env"
chown root:root "${report_dir}/empty.env"
chmod 0444 "${report_dir}/empty.env"

touch "${report_dir}/checks.txt" "${report_dir}/logs.txt"
chown codex-audit:codex-audit "${report_dir}/checks.txt"
chown root:codex-audit "${report_dir}/logs.txt"
chmod 0640 "${report_dir}/checks.txt" "${report_dir}/logs.txt"

for unit in \
    sp2-audit-runtime.service \
    sp2-audit-runtime.timer \
    sp2-audit-tests.timer
do
    install -o root -g root -m 0644 \
        "${source_dir}/systemd/${unit}" \
        "/etc/systemd/system/${unit}"
done

sed "s|@@APP_DIR@@|${app_dir}|g" \
    "${source_dir}/systemd/sp2-audit-tests.service" \
    > /etc/systemd/system/sp2-audit-tests.service
chown root:root /etc/systemd/system/sp2-audit-tests.service
chmod 0644 /etc/systemd/system/sp2-audit-tests.service

systemctl daemon-reload
systemctl enable --now sp2-audit-runtime.timer
systemctl enable --now sp2-audit-tests.timer

systemctl start sp2-audit-runtime.service

if ! systemctl start sp2-audit-tests.service; then
    echo "Nocny test wykrył problem; bezpieczny wynik zapisano w checks.txt."
fi

echo
systemctl is-active sp2-audit-runtime.timer
systemctl is-active sp2-audit-tests.timer
echo
echo "Raport diagnostyczny:"
cat "${report_dir}/logs.txt"
echo
echo "Raport testów:"
cat "${report_dir}/checks.txt"
