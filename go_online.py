"""
Put the dashboard on the internet from this computer: one command, one window.

    python go_online.py                          # prints the address, opens it
    python go_online.py --site https://you.netlify.app

It starts the server (refusing to if nobody can sign in), starts a free Cloudflare
quick tunnel to it, waits until the public address answers, and opens the Netlify
page already pointed at it (or the address itself without --site). Closing the
window, or Ctrl+C, stops both. The address changes every run; the page learns it
from the link, so nothing needs rebuilding.

cloudflared is taken from PATH or proxy/bin, else downloaded once from Cloudflare's
GitHub release and checked against the SHA-256 published with it.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path

import envfile

HERE = Path(__file__).parent

RELEASE = "https://api.github.com/repos/cloudflare/cloudflared/releases/latest"

ADDRESS = re.compile(r"https://[a-z0-9-]+\.trycloudflare\.com")


def asset_name(system=None, machine=None):
    """The cloudflared release file for this computer, or None."""

    system = (system or platform.system()).lower()
    machine = (machine or platform.machine()).lower()

    arm = machine in ("arm64", "aarch64")

    if system == "windows" and not arm:
        return "cloudflared-windows-amd64.exe"

    if system == "linux":
        return "cloudflared-linux-arm64" if arm else "cloudflared-linux-amd64"

    return None


def tunnel_address(line):
    """The public address in a line of cloudflared's output, if it has one."""

    found = ADDRESS.search(line)

    return found.group(0) if found else None


def site_origin(value):
    """https://host from whatever was typed, or None."""

    value = (value or "").split(",")[0].strip().rstrip("/")

    return value if re.fullmatch(r"https?://[A-Za-z0-9.-]+(:\d{1,5})?", value) else None


def sha256_of(path):

    digest = hashlib.sha256()

    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)

    return digest.hexdigest()


def fetch(url, timeout=60):

    request = urllib.request.Request(url, headers={"User-Agent": "bayesian-ids"})

    return urllib.request.urlopen(request, timeout=timeout)


def find_cloudflared(bin_dir=HERE / "proxy" / "bin"):

    exe = "cloudflared.exe" if os.name == "nt" else "cloudflared"

    local = bin_dir / exe

    if local.is_file():
        return str(local)

    return shutil.which("cloudflared")


def download_cloudflared(bin_dir=HERE / "proxy" / "bin", opener=fetch):
    """Download and verify cloudflared. Returns its path; raises if it cannot be verified."""

    name = asset_name()

    if not name:
        raise RuntimeError("No cloudflared download for this system; install it from "
                           "https://github.com/cloudflare/cloudflared/releases and run again.")

    release = json.load(opener(RELEASE))

    asset = next((a for a in release["assets"] if a["name"] == name), None)

    expected = (asset or {}).get("digest", "")

    if not expected.startswith("sha256:"):
        raise RuntimeError("The release lists no SHA-256 for cloudflared, so it was not installed.")

    bin_dir.mkdir(parents=True, exist_ok=True)

    target = bin_dir / ("cloudflared.exe" if os.name == "nt" else "cloudflared")
    partial = target.with_suffix(".part")

    print(f"Downloading cloudflared {release['tag_name']} ...")

    with opener(asset["browser_download_url"], timeout=300) as response, open(partial, "wb") as out:
        shutil.copyfileobj(response, out)

    if sha256_of(partial) != expected.removeprefix("sha256:"):
        partial.unlink()
        raise RuntimeError("The downloaded cloudflared did not match its published SHA-256; discarded.")

    # a virus scanner may hold the new file for a moment on Windows
    for attempt in range(20):
        try:
            os.replace(partial, target)
            break
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(1)

    if os.name != "nt":
        target.chmod(0o755)

    print("cloudflared verified and installed in", bin_dir)

    return str(target)


def duckdns_update(domain, token, text, opener=fetch):
    """Publish text (the tunnel address) as the TXT record of a DuckDNS name; '' clears it.

    Browsers read it back through public DNS-over-HTTPS, so the pages find the server by
    itself even though the address changes on every start. Returns True when DuckDNS said OK.
    """

    name = domain.removesuffix(".duckdns.org")

    query = urllib.parse.urlencode({
        "domains": name, "token": token, "verbose": "true",
        **({"txt": text} if text else {"txt": "", "clear": "true"})
    })

    try:
        with opener(f"https://www.duckdns.org/update?{query}", timeout=20) as response:
            return response.read().decode().split()[0] == "OK"
    except Exception:
        return False


def healthy(url, timeout=5):

    try:
        with fetch(f"{url}/api/healthz", timeout=timeout) as response:
            return response.status == 200
    except Exception:
        return False


def signs_in(url, attempts=1, wait=3):
    """True when the server at url demands a sign-in, False when it plainly does not, and None when
    it could not be asked (a network hiccup is not proof either way)."""

    for attempt in range(attempts):

        try:
            with fetch(f"{url}/api/auth", timeout=10) as response:
                return json.load(response).get("required") is True
        except Exception:
            if attempt + 1 < attempts:
                time.sleep(wait)

    return None


def ensure_account(env):
    """Make sure someone can sign in; offer to create the admin if not."""

    import serve

    db = env.get("IDS_DB", "ids.db")

    if env.get("IDS_ADMIN_TOKEN") or serve.accounts_exist(db):
        return True

    if not sys.stdin.isatty():
        print("No account exists. Run: python manage_users.py add NAME --role admin")
        return False

    print("\nNobody can sign in yet, and the site will be public. Create the admin account.")

    name = input("Admin username: ").strip()

    if not name:
        return False

    done = subprocess.call(
        [sys.executable, str(HERE / "manage_users.py"), "add", name, "--role", "admin"], env=env
    )

    return done == 0 and serve.accounts_exist(db)


def stop(process):

    if process and process.poll() is None:
        process.terminate()


def open_tunnel(cloudflared, local, wait=60):
    """Start cloudflared. Returns (process, public address or None)."""

    tunnel = subprocess.Popen([cloudflared, "tunnel", "--no-autoupdate", "--url", local],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

    found = []

    def watch():
        for line in tunnel.stdout:
            address = tunnel_address(line)
            if address and not found:
                found.append(address)

    threading.Thread(target=watch, daemon=True).start()

    deadline = time.time() + wait

    while not found and time.time() < deadline and tunnel.poll() is None:
        time.sleep(0.3)

    return tunnel, (found[0] if found else None)


def wait_until_healthy(url, attempts=60):

    for _ in range(attempts):

        if healthy(url):
            return True

        time.sleep(2)

    return False


def main(argv=None):

    envfile.load()

    parser = argparse.ArgumentParser(description="Put the dashboard online through a free Cloudflare tunnel.")
    parser.add_argument("--site", default=os.environ.get("IDS_SITE_URL") or os.environ.get("IDS_CORS_ORIGINS"),
                        help="your Netlify address; without it the tunnel address itself is opened")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--no-browser", action="store_true")

    args = parser.parse_args(argv)

    site = site_origin(args.site)

    env = dict(os.environ)

    if site:
        env["IDS_CORS_ORIGINS"] = site

    if not ensure_account(env):
        return "Cancelled: the dashboard will not go online without a way to sign in."

    local = f"http://127.0.0.1:{args.port}"

    if healthy(local):
        return (f"Something already answers on port {args.port}. Close it (an older dashboard window?) "
                "or pick another with --port.")

    cloudflared = find_cloudflared() or download_cloudflared()

    env["IDS_LAUNCHER"] = "go_online"

    server = subprocess.Popen([sys.executable, str(HERE / "serve.py"), "--public", "--port", str(args.port)],
                              cwd=HERE, env=env)

    domain = (os.environ.get("DUCKDNS_DOMAIN") or "").strip().lower()
    token = (os.environ.get("DUCKDNS_TOKEN") or "").strip()

    tunnel = None

    try:
        for _ in range(120):

            if server.poll() is not None:
                return "The server stopped; see its message above."

            if healthy(local):
                break

            time.sleep(0.5)
        else:
            return "The server did not start in time."

        first = True

        def alive():
            """The server runs, or it restarted itself (the dashboard's Restart button starts
            a new process, so the one started here ends while the site stays up)."""

            if server.poll() is None:
                return True

            for _ in range(45):

                if healthy(local):
                    return True

                time.sleep(2)

            return False

        # the tunnel is restarted whenever it drops; the server keeps running
        while alive():

            tunnel, public = open_tunnel(cloudflared, local)

            if not public:
                print("The tunnel did not come up; trying again in 15 seconds.")
                stop(tunnel)
                time.sleep(15)
                continue

            print(f"Tunnel address: {public}")
            print("Waiting for it to answer (up to 40 seconds) ...")

            reached = wait_until_healthy(public, attempts=20)

            if not reached:
                print(
                    "This computer could not reach that address yet. New tunnel names often take a minute "
                    "to become visible to a home router's DNS cache, and other devices usually see them sooner. "
                    "Carrying on: the page will connect as soon as it can. If it never does, run "
                    "ipconfig /flushdns, or set this computer's DNS to 1.1.1.1 or 8.8.8.8, and start again."
                )

            # the server itself refuses to run public without a sign-in. Stop only on a clear "no":
            # failing to ask is not evidence, and the local answer already settled it
            if signs_in(local, attempts=5) is not True:
                return "SAFETY STOP: the server does not require sign-in (or could not be asked). Not publishing it."

            if reached and signs_in(public, attempts=3) is False:
                return "SAFETY STOP: the public address does not require sign-in. Not opening it."

            published = ""

            if domain and token:

                if duckdns_update(domain, token, public):
                    published = f"  (published as the TXT record of {domain}, so the pages find it by themselves)"
                else:
                    published = "  (could not publish it to DuckDNS: check DUCKDNS_DOMAIN and DUCKDNS_TOKEN)"

            link = public

            if site:
                link = f"{site}/?api={public}" + (f"&name={domain}" if domain else "")

            print(f"\nOnline.  Open this on any device:\n\n    {link}\n{published}")

            if first:
                print("Sign in with your admin account. Leave this window open; Ctrl+C takes the site offline.")

                if not args.no_browser:
                    webbrowser.open(link)

                first = False

            while tunnel.poll() is None and (server.poll() is None or healthy(local)):
                time.sleep(2 if server.poll() is None else 5)

            if tunnel.poll() is not None:
                print("The tunnel dropped; reconnecting ...")
                stop(tunnel)
                time.sleep(5)

        return "The server stopped."
    except KeyboardInterrupt:
        return "Stopped."
    finally:
        stop(tunnel)
        stop(server)

        if domain and token:
            duckdns_update(domain, token, "")


if __name__ == "__main__":

    sys.exit(main())
