"""
One-time setup so that opening your Netlify site is all it takes from then on.

    python setup_online.py

It asks for your Netlify address and (optionally) your free DuckDNS name and token, checks
them, makes sure an admin account exists, writes .env, and registers the online launcher
to start when you sign in to this computer. Afterwards: switch the computer on, open the
Netlify site, sign in.

The DuckDNS name lets the Netlify pages find the server by themselves: the launcher
publishes the tunnel's current address as a TXT record and the pages read it. Without
DuckDNS the launcher opens the right link for you, but another device would need it typed.
"""
import getpass
import os
import re
import subprocess
import sys
from pathlib import Path

import go_online
from autostart import Autostart

HERE = Path(__file__).parent


def update_env_file(path, values):
    """Set KEY=value lines in a .env file, keeping everything else (and comments) as it was."""

    path = Path(path)

    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []

    remaining = dict(values)

    for i, line in enumerate(lines):

        key = re.match(r"\s*#?\s*([A-Z][A-Z0-9_]*)\s*=", line)

        # a commented example such as "# IDS_SITE_URL=..." is replaced by the real setting
        if key and key.group(1) in remaining:
            lines[i] = f"{key.group(1)}={remaining.pop(key.group(1))}"

    lines += [f"{k}={v}" for k, v in remaining.items()]

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    try:
        path.chmod(0o600)
    except OSError:
        pass


def ask(question, default=""):

    answer = input(f"{question}{f' [{default}]' if default else ''}: ").strip()

    return answer or default


def main():

    print(__doc__)

    env = HERE / ".env"

    site = None

    while not site:

        site = go_online.site_origin(ask("Your Netlify address (https://something.netlify.app)",
                                          os.environ.get("IDS_SITE_URL", "")))

        if not site:
            print("  That does not look like an address. Include https://")

    values = {"IDS_SITE_URL": site}

    print("\nDuckDNS (free, https://www.duckdns.org) lets the pages find your server by themselves.")

    domain = ask("Your DuckDNS name, e.g. myids.duckdns.org (empty to skip)").lower()

    if domain:

        domain = domain if domain.endswith(".duckdns.org") else f"{domain}.duckdns.org"

        token = getpass.getpass("Your DuckDNS token (hidden while typing): ").strip()

        print("Checking the token ...")

        if go_online.duckdns_update(domain, token, "setup-check") and go_online.duckdns_update(domain, token, ""):
            print("  DuckDNS accepted it.")
            values.update({"DUCKDNS_DOMAIN": domain, "DUCKDNS_TOKEN": token})
        else:
            print("  DuckDNS refused that name/token pair. Skipping it; run this again to retry.")
            domain = ""

    update_env_file(env, values)

    print(f"\nWrote {env} (keep it private; it is excluded from git).")

    import serve

    if not (os.environ.get("IDS_ADMIN_TOKEN") or serve.accounts_exist(os.environ.get("IDS_DB", "ids.db"))):

        print("\nNo account exists yet. Create the admin account you will sign in with.")

        name = ask("Admin username", "admin")

        if subprocess.call([sys.executable, str(HERE / "manage_users.py"), "add", name, "--role", "admin"]) != 0:
            return "Setup stopped: no admin account."

    autostart = Autostart()

    if autostart.supported and ask("\nStart the online dashboard automatically when you sign in to this computer? (y/n)",
                                   "y").lower().startswith("y"):

        (HERE / "logs").mkdir(exist_ok=True)

        try:
            autostart.enable([sys.executable, str(HERE / "go_online.py"), "--no-browser"], HERE,
                             HERE / "logs" / "online.log")
            print("  Registered. It starts at your next sign-in (or run go_online.py now).")
        except RuntimeError as error:
            print(f"  Could not register it: {error}")

    print("\nLast step: publish the pages once, so they know your DuckDNS name:")
    print("    cd frontend")

    if domain:
        print(f'    $env:VITE_DISCOVERY_NAME = "{domain}"      (PowerShell)')

    print("    npm run build")
    print("    then drag frontend\\dist onto https://app.netlify.com/drop")

    print("\nFrom then on: switch the computer on, open", site, "and sign in.")

    return None


if __name__ == "__main__":

    sys.exit(main())
