#!/usr/bin/env bash
# Set up the always-on server on a fresh Ubuntu or Debian machine:
#
#   sudo ./install.sh                         # asks for the name and the admin account
#   sudo ./install.sh --domain ids.example.com --site https://you.netlify.app
#
# It installs Docker if needed, opens ports 22, 80 and 443 in the firewall (ufw), writes .env,
# creates the admin account, then builds and starts the dashboard with HTTPS. Run it from a
# copy of the whole project (it builds the image from the project root).
#
# Before you run it: make the domain point at this machine, or Let's Encrypt cannot issue the
# certificate. Nothing is changed beyond Docker, ufw rules and this folder.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

domain=""
site=""
admin=""

while [ $# -gt 0 ]; do
  case "$1" in
    --domain) domain="${2:?--domain needs a value}"; shift 2 ;;
    --site)   site="${2:?--site needs a value}"; shift 2 ;;
    --admin)  admin="${2:?--admin needs a value}"; shift 2 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this as root: sudo $0" >&2
  exit 1
fi

if [ ! -f "$here/../../serve.py" ]; then
  echo "This does not look like a copy of the whole project: $here/../../serve.py is missing." >&2
  exit 1
fi

if [ ! -f "$here/../../bayesian_ids.pkl" ]; then
  echo "bayesian_ids.pkl is missing. Train a model (python train_model.py) and copy it into the project first:" >&2
  echo "the image carries the trained model, not the dataset." >&2
  exit 1
fi

# -- Docker ---------------------------------------------------------------------------------

if ! command -v docker >/dev/null 2>&1; then
  echo "Installing Docker ..."
  apt-get update -y
  apt-get install -y docker.io docker-compose-v2
  systemctl enable --now docker
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "Installing the Docker compose plugin ..."
  apt-get update -y
  apt-get install -y docker-compose-v2
fi

# -- firewall ---------------------------------------------------------------------------------

if command -v ufw >/dev/null 2>&1; then
  ufw allow 22/tcp >/dev/null
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  ufw --force enable >/dev/null
  echo "Firewall: only 22, 80 and 443 are open."
else
  echo "ufw is not installed: make sure only ports 22, 80 and 443 are reachable (not 8000)." >&2
fi

# -- settings -----------------------------------------------------------------------------------

cd "$here"

if [ -z "$domain" ]; then
  read -r -p "The name people will open (e.g. ids.example.com): " domain
fi

if ! [[ "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]]; then
  echo "That is not a valid host name: $domain" >&2
  exit 1
fi

if [ -z "$site" ]; then
  read -r -p "Netlify address that may call this server (empty if you do not use Netlify): " site
fi

if [ -n "$site" ] && ! [[ "$site" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?$ ]]; then
  echo "That is not an address like https://name.netlify.app: $site" >&2
  exit 1
fi

if [ ! -f .env ]; then
  cp .env.example .env
  chmod 600 .env
fi

set_env() {
  # replace an existing (even commented) KEY=... line, else append
  if grep -qE "^#? ?$1=" .env; then
    sed -i -E "s|^#? ?$1=.*|$1=$2|" .env
  else
    echo "$1=$2" >> .env
  fi
}

set_env IDS_DOMAIN "$domain"
[ -n "$site" ] && set_env IDS_CORS_ORIGINS "$site"

# -- image and admin account ----------------------------------------------------------------------

echo "Building the image (a few minutes the first time) ..."
docker compose build

echo
echo "Create the administrator account you will sign in with."
if [ -z "$admin" ]; then
  read -r -p "Admin username: " admin
fi
docker compose run --rm ids python manage_users.py add "$admin" --role admin

# -- go ---------------------------------------------------------------------------------------------

docker compose up -d

echo
echo "Started. Caddy is getting a certificate for $domain; this takes a minute."
echo "Check:   docker compose ps          docker compose logs -f caddy"
echo "Open:    https://$domain"
if [ -n "$site" ]; then
  echo
  echo "For your Netlify site, build the pages once with this backend address and upload them:"
  echo "    cd frontend && VITE_API_URL=https://$domain npm run build"
fi
