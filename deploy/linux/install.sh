#!/usr/bin/env bash
# Install the Bayesian IDS as a systemd service (Debian/Ubuntu/RHEL family).
#
#     sudo ./deploy/linux/install.sh            # from a checkout of the project
#
# Before running: train the model (bayesian_ids.pkl must exist) and build the
# dashboard (cd frontend && npm run build). The dataset is NOT needed on the
# server; the demo is simply unavailable without it.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo $0" >&2
    exit 1
fi

SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TARGET=/opt/bayesian-ids
DATA=/var/lib/bayesian-ids
LOGS=/var/log/bayesian-ids
CONFIG=/etc/bayesian-ids

for needed in bayesian_ids.pkl serve.py frontend/dist/index.html; do
    if [[ ! -e "$SOURCE/$needed" ]]; then
        echo "Missing $needed in $SOURCE (see the comments at the top of this script)." >&2
        exit 1
    fi
done

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }

id ids >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin ids

install -d -o ids -g ids -m 750 "$DATA" "$DATA/captures" "$LOGS"
install -d -o root -g ids -m 750 "$CONFIG"
install -d -m 755 "$TARGET"

# Code and model only: no dataset, no node_modules, no local databases or certs
tar -C "$SOURCE" \
    --exclude='./dataset' --exclude='./frontend/node_modules' --exclude='./frontend/src' \
    --exclude='./tests' --exclude='./.venv' --exclude='./venv' --exclude='__pycache__' \
    --exclude='./logs' --exclude='./certs' --exclude='./ids.db*' --exclude='./captures' \
    -cf - . | tar -C "$TARGET" -xf -

python3 -m venv "$TARGET/venv"
"$TARGET/venv/bin/pip" install --quiet --upgrade pip
"$TARGET/venv/bin/pip" install --quiet -r "$TARGET/requirements-prod.txt"

if [[ ! -f "$CONFIG/env" ]]; then
    install -m 640 -o root -g ids "$SOURCE/deploy/linux/env.example" "$CONFIG/env"
    echo "Created $CONFIG/env: review it before exposing the server."
fi

# Fallback for kernels/unit settings that drop ambient capabilities
if command -v setcap >/dev/null; then
    setcap cap_net_raw,cap_net_admin=eip "$(readlink -f "$TARGET/venv/bin/python3")" || true
fi

install -m 644 "$SOURCE/deploy/linux/bayesian-ids.service" /etc/systemd/system/bayesian-ids.service

systemctl daemon-reload
systemctl enable --now bayesian-ids.service

echo
echo "Installed. Status:   systemctl status bayesian-ids"
echo "Logs:                journalctl -u bayesian-ids -f"
echo "Health:              curl http://127.0.0.1:8000/api/healthz"
echo "First admin account: see the comment in $CONFIG/env"
