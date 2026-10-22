"""
The proxy manager: settings, generated configuration, verified installs and,
with the real Caddy and nginx programs, actually proxying.

Install tests run against a local fake release site, so they need no network.
The programs themselves come from proxy/bin (install them from the dashboard);
those tests are skipped where they are missing.
"""
import hashlib
import json
import os
import socket
import threading
import zipfile
import tarfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import proxy_manager as pm
from proxy_manager import (
    ProxyError, ProxyManager, bind_addresses, caddy_environment, check_settings,
    nginx_config
)
from storage import Store

REAL_BIN = pm.HERE / "proxy" / "bin"

needs_caddy = pytest.mark.skipif(
    not (REAL_BIN / pm.exe("caddy")).exists(), reason="install Caddy from the dashboard first"
)

needs_nginx = pytest.mark.skipif(
    not (REAL_BIN / "nginx" / pm.exe("nginx")).exists(), reason="install nginx from the dashboard first"
)


def free_port():

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# -- settings --------------------------------------------------------------------------

def test_defaults_are_local_only_and_valid():

    settings = check_settings({})

    assert settings["engine"] == "caddy" and settings["port"] == 8443
    assert settings["expose"] is False and settings["tls"] == "internal"
    assert bind_addresses(settings) == ["127.0.0.1", "::1"]


@pytest.mark.parametrize("incoming, message", [
    ({"engine": "apache"}, "engine"),
    ({"address": "bad host!"}, "address"),
    ({"address": "-nope.example.com"}, "address"),
    ({"address": ""}, "address"),
    ({"port": 0}, "port"),
    ({"port": 70000}, "port"),
    ({"port": "443"}, "port"),
    ({"port": True}, "port"),
    ({"tls": "maybe"}, "TLS for Caddy"),
    ({"engine": "nginx", "cert": "a.crt"}, "both"),
    ({"engine": "nginx", "key": "a.key"}, "both"),
])
def test_bad_settings_are_refused_with_a_reason(incoming, message):

    with pytest.raises(ProxyError, match=message):
        check_settings(incoming)


@pytest.mark.parametrize("address", ["localhost", "ids.example.com", "10.1.2.3", "::1", "a-b.c"])
def test_ordinary_addresses_are_accepted(address):

    assert check_settings({"address": address})["address"] == address


def test_caddy_takes_internal_or_an_email_and_ignores_certificate_files():

    assert check_settings({"tls": "me@example.com"})["tls"] == "me@example.com"

    assert check_settings({"cert": "a.crt", "key": "a.key"})["cert"] is None


def test_nginx_certificate_files_must_exist_and_come_as_a_pair():

    present = lambda name: name in ("a.crt", "a.key")

    ok = check_settings({"engine": "nginx", "cert": "a.crt", "key": "a.key"}, cert_exists=present)

    assert ok["tls"] == "files" and ok["cert"] == "a.crt"

    with pytest.raises(ProxyError, match="not in the certificates folder"):
        check_settings({"engine": "nginx", "cert": "a.crt", "key": "gone.key"}, cert_exists=present)

    assert check_settings({"engine": "nginx"})["tls"] == "self-signed"


def test_exposing_the_proxy_listens_on_every_interface():

    assert bind_addresses({"expose": True}) == ["0.0.0.0", "::"]


# -- generated configuration -----------------------------------------------------------------

PATHS = {"install": "C:/Program Files/IDS/nginx", "run": "C:/Users/me/IDS proxy/run/nginx",
         "cert": "C:/c/cert.pem", "key": "C:/c/key.pem"}


def conf(**overrides):

    settings = {**pm.DEFAULTS, "engine": "nginx", "tls": "self-signed", **overrides}

    return nginx_config(settings, "127.0.0.1:8000", 4097, PATHS)


def test_nginx_listens_on_both_loopbacks_by_default():

    text = conf()

    assert "listen 127.0.0.1:8443 ssl;" in text
    assert "listen [::1]:8443 ssl;" in text
    assert "0.0.0.0" not in text


def test_nginx_exposed_listens_everywhere():

    text = conf(expose=True, port=443)

    assert "listen 0.0.0.0:443 ssl;" in text and "listen [::]:443 ssl;" in text


def test_nginx_streams_uploads_and_allows_the_dashboards_limit():

    text = conf()

    assert "client_max_body_size 4097m;" in text
    assert "proxy_request_buffering off;" in text
    assert "proxy_buffering off;" in text
    assert "proxy_read_timeout 3600s;" in text


def test_nginx_never_passes_on_a_clients_own_forwarding_claim():

    text = conf()

    assert "proxy_set_header X-Forwarded-For $remote_addr;" in text
    assert "$proxy_add_x_forwarded_for" not in text
    assert "proxy_set_header X-Forwarded-Proto $scheme;" in text


def test_nginx_forwards_websockets_and_hides_its_version():

    text = conf()

    assert "proxy_set_header Upgrade $http_upgrade;" in text
    assert "proxy_set_header Connection $connection_upgrade;" in text
    assert "server_tokens off;" in text
    assert "http2 on;" in text
    assert "ssl_protocols TLSv1.2 TLSv1.3;" in text


def test_nginx_paths_are_quoted_and_use_forward_slashes():

    text = conf()

    assert 'include "C:/Program Files/IDS/nginx/conf/mime.types";' in text
    assert 'error_log "C:/Users/me/IDS proxy/run/nginx/logs/error.log" warn;' in text
    assert 'ssl_certificate "C:/c/cert.pem";' in text
    assert "\\" not in text


def test_nginx_proxies_to_the_dashboard_and_serves_the_chosen_name():

    text = conf(address="ids.example.com")

    assert "proxy_pass http://127.0.0.1:8000;" in text
    assert "server_name ids.example.com;" in text


def test_caddy_environment_matches_the_settings():

    local = caddy_environment({**pm.DEFAULTS}, "127.0.0.1:8000", 4097, "D:/data")

    assert local["IDS_PROXY_ADDRESS"] == "localhost:8443"
    assert local["IDS_UPSTREAM"] == "127.0.0.1:8000"
    assert local["IDS_TLS"] == "internal"
    assert local["IDS_UPLOAD_LIMIT"] == str(4097 * 1024 * 1024)
    assert local["IDS_BIND"] == "127.0.0.1 ::1"
    assert local["IDS_AUTO_HTTPS"] == "disable_redirects"

    public = caddy_environment(
        {**pm.DEFAULTS, "address": "ids.example.com", "port": 443, "expose": True, "tls": "me@example.com"},
        "127.0.0.1:8000", 4097, "D:/data"
    )

    assert public["IDS_AUTO_HTTPS"] == "ignore_loaded_certs" and public["IDS_BIND"] == "0.0.0.0 ::"
    assert public["IDS_TLS"] == "me@example.com"


# -- verified installs ---------------------------------------------------------------------------

class FakeSite:
    """A local stand-in for GitHub releases and nginx.org."""

    def __init__(self):

        self.files = {}
        self.redirects = {}

        outer = self

        class Handler(BaseHTTPRequestHandler):

            def do_HEAD(self):
                self.route(head=True)

            def do_GET(self):
                self.route(head=False)

            def route(self, head):

                if self.path in outer.redirects:
                    self.send_response(302)
                    self.send_header("Location", outer.redirects[self.path])
                    self.end_headers()
                    return

                body = outer.files.get(self.path)

                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return

                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()

                if not head:
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)

        threading.Thread(target=self.server.serve_forever, daemon=True).start()

        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()


@pytest.fixture
def site():

    fake = FakeSite()

    yield fake

    fake.close()


def caddy_archive(tmp_path, version, payload=b"fake caddy program"):
    """An archive in the format this platform's download uses."""

    system, arch = pm.platform_names()

    name = f"caddy_{version}_{system}_{arch}." + ("zip" if system == "windows" else "tar.gz")

    path = tmp_path / name

    if system == "windows":
        with zipfile.ZipFile(path, "w") as z:
            z.writestr("caddy.exe", payload)
            z.writestr("LICENSE", "x")
    else:
        program = tmp_path / "caddy"
        program.write_bytes(payload)
        with tarfile.open(path, "w:gz") as t:
            t.add(program, arcname="caddy")

    return name, path.read_bytes()


def publish_caddy(site, tmp_path, version="9.9.9", payload=b"fake caddy program", lie=False):

    name, data = caddy_archive(tmp_path, version, payload)

    digest = hashlib.sha512(b"something else" if lie else data).hexdigest()

    site.redirects["/latest"] = f"{site.url}/tag/v{version}"
    site.files[f"/tag/v{version}"] = b""
    site.files[f"/download/v{version}/{name}"] = data
    site.files[f"/download/v{version}/caddy_{version}_checksums.txt"] = f"{digest}  {name}\n".encode()


def test_caddy_is_installed_after_its_checksum_matches(site, tmp_path):

    publish_caddy(site, tmp_path)

    target = tmp_path / "bin"

    manifest = pm.install_caddy(releases=site.url, target=target)

    assert manifest["version"] == "9.9.9"
    assert "SHA-512" in manifest["verified"]
    assert (target / pm.exe("caddy")).read_bytes() == b"fake caddy program"
    assert manifest["sha256"] == hashlib.sha256(b"fake caddy program").hexdigest()

    assert json.loads((target / "caddy.json").read_text())["version"] == "9.9.9"


def test_a_caddy_download_that_does_not_match_is_not_installed(site, tmp_path):

    publish_caddy(site, tmp_path, lie=True)

    target = tmp_path / "bin"

    with pytest.raises(ProxyError, match="checksum"):
        pm.install_caddy(releases=site.url, target=target)

    # nothing was unpacked
    assert not target.exists() or not any(target.iterdir())


def test_a_missing_checksum_line_is_a_refusal_too(site, tmp_path):

    publish_caddy(site, tmp_path)

    for path in list(site.files):
        if path.endswith("_checksums.txt"):
            site.files[path] = b"abc123  some_other_file.zip\n"

    with pytest.raises(ProxyError, match="no checksum"):
        pm.install_caddy(releases=site.url, target=tmp_path / "bin")


def test_the_latest_caddy_version_follows_the_redirect(site, tmp_path):

    publish_caddy(site, tmp_path, version="3.4.5")

    assert pm.latest_caddy_version(site.url) == "3.4.5"


def test_the_newest_stable_nginx_is_found_numerically(site):

    names = ["1.29.5", "1.30.2", "1.30.10", "1.30.9", "1.31.0"]

    site.files["/download/"] = "".join(f'<a href="nginx-{n}.zip">nginx-{n}.zip</a>' for n in names).encode()

    # even minor = stable; 1.30.10 beats 1.30.9 (a string sort would get this wrong)
    assert pm.latest_nginx_stable(site.url) == "1.30.10"

    site.files["/download/"] = b"<html>nothing here</html>"

    with pytest.raises(ProxyError, match="stable"):
        pm.latest_nginx_stable(site.url)


GPG = pm.find_gpg()

needs_gpg_and_windows = pytest.mark.skipif(
    not (GPG and os.name == "nt"), reason="needs GnuPG on Windows"
)


DATA = pm.HERE / "tests" / "data"


def publish_nginx(site, version="1.30.9", tamper=False):
    """A fake nginx.org serving a fixed archive with a real PGP signature.

    The archive, its signature and the (test-only) public key are static files in
    tests/data: this GnuPG can verify anywhere but only sign inside its own shell.
    """

    data = (DATA / "nginx-1.30.9.zip").read_bytes()

    if tamper:
        # a different archive under the original signature
        data = data.replace(b"fake nginx program", b"MALICIOUS program!")

    site.files["/download/"] = f'<a href="nginx-{version}.zip">x</a>'.encode()
    site.files[f"/download/nginx-{version}.zip"] = data
    site.files[f"/download/nginx-{version}.zip.asc"] = (DATA / "nginx-1.30.9.zip.asc").read_bytes()
    site.files["/en/pgp_keys.html"] = b'<a href="/keys/signer.key">key</a>'
    site.files["/keys/signer.key"] = (DATA / "signer.key").read_bytes()


@needs_gpg_and_windows
def test_nginx_is_installed_after_its_pgp_signature_checks_out(site, tmp_path):

    publish_nginx(site)

    manifest = pm.install_nginx(site=site.url, target=tmp_path / "bin")

    assert manifest["version"] == "1.30.9"
    assert "PGP signature verified" in manifest["verified"]
    assert "B9CF29C4EC2E01674DB5295AEE95FE245B91C085" in manifest["verified"]
    assert (tmp_path / "bin" / "nginx" / "nginx.exe").read_bytes() == b"fake nginx program"
    assert (tmp_path / "bin" / "nginx" / "conf" / "mime.types").exists()


@needs_gpg_and_windows
def test_an_nginx_archive_that_does_not_match_its_signature_is_not_installed(site, tmp_path):

    publish_nginx(site, tamper=True)

    target = tmp_path / "bin"

    with pytest.raises(ProxyError, match="signature is not valid"):
        pm.install_nginx(site=site.url, target=target)

    assert not (target / "nginx").exists()


@needs_gpg_and_windows
def test_without_gnupg_nginx_is_refused_unless_you_say_otherwise(site, tmp_path):

    publish_nginx(site)

    with pytest.raises(ProxyError, match="GnuPG"):
        pm.install_nginx(site=site.url, target=tmp_path / "bin", gpg=False)

    manifest = pm.install_nginx(site=site.url, target=tmp_path / "bin", gpg=False, allow_unverified=True)

    assert manifest["verified"].startswith("NOT verified")


# -- the manager's own logic ---------------------------------------------------------------------

@pytest.fixture
def run_area(tmp_path, monkeypatch):

    monkeypatch.setenv("IDS_PROXY_DIR", str(tmp_path / "proxy"))
    monkeypatch.setenv("IDS_PROXY_BIN", str(tmp_path / "proxy" / "bin"))

    (tmp_path / "proxy" / "bin").mkdir(parents=True)

    return tmp_path / "proxy"


@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "p.db"))

    yield store

    store.close()


def manager(store, tmp_path, auth=True):

    return ProxyManager(store, lambda: "127.0.0.1:8000", lambda: 4097, lambda: auth,
                        cert_dir=str(tmp_path / "certs"))


def fake_caddy(run_area, payload=b"not a real program"):

    binary = run_area / "bin" / pm.exe("caddy")

    binary.write_bytes(payload)

    (run_area / "bin" / "caddy.json").write_text(json.dumps({
        "engine": "caddy", "version": "1", "verified": "test",
        "sha256": hashlib.sha256(payload).hexdigest()
    }))

    return binary


def test_a_program_found_in_the_proxy_folder_is_adopted_and_then_checksummed(run_area, store, tmp_path):

    binary = run_area / "bin" / pm.exe("caddy")

    binary.write_bytes(b"installed by the script")

    proxy = manager(store, tmp_path)

    assert proxy.manifest("caddy") is None

    proxy.adopt_existing()

    manifest = proxy.manifest("caddy")

    assert manifest["installed"] and manifest["intact"]

    # a second call does not re-bless a program that changed in between
    binary.write_bytes(b"swapped out")

    proxy.adopt_existing()

    assert proxy.manifest("caddy")["intact"] is False


def test_a_program_that_changed_since_install_will_not_start(run_area, store, tmp_path):

    binary = fake_caddy(run_area)

    proxy = manager(store, tmp_path)

    assert proxy.manifest("caddy")["intact"]

    binary.write_bytes(b"tampered")

    with pytest.raises(ProxyError, match="no longer matches"):
        proxy.start()


def test_starting_an_engine_that_is_not_installed_says_so(run_area, store, tmp_path):

    with pytest.raises(ProxyError, match="not installed"):
        manager(store, tmp_path).start()


def test_exposing_the_dashboard_needs_sign_in_first(run_area, store, tmp_path):

    fake_caddy(run_area)

    proxy = manager(store, tmp_path, auth=False)

    proxy.save({"expose": True})

    with pytest.raises(ProxyError, match="create an account first"):
        proxy.start()


def test_a_busy_port_is_reported_not_overwritten(run_area, store, tmp_path):

    fake_caddy(run_area)

    proxy = manager(store, tmp_path)

    with socket.socket() as busy:

        busy.bind(("127.0.0.1", 0))
        busy.listen()

        proxy.save({"port": busy.getsockname()[1]})

        with pytest.raises(ProxyError, match="already in use"):
            proxy.start()


def test_settings_survive_in_the_database_and_engine_cannot_change_while_running(run_area, store, tmp_path, monkeypatch):

    proxy = manager(store, tmp_path)

    proxy.save({"engine": "nginx", "port": 9443, "address": "ids.local"})

    again = manager(store, tmp_path)

    assert again.settings()["engine"] == "nginx" and again.settings()["port"] == 9443

    monkeypatch.setattr(ProxyManager, "running", lambda self: True)

    with pytest.raises(ProxyError, match="stop the proxy"):
        proxy.save({"engine": "caddy"})


def test_the_status_lists_what_is_installed_and_which_certificates_exist(run_area, store, tmp_path):

    fake_caddy(run_area)

    (tmp_path / "certs").mkdir()

    for name in ("site.crt", "site.key", "notes.txt"):
        (tmp_path / "certs" / name).write_text("x")

    status = manager(store, tmp_path).status()

    assert status["installed"]["caddy"]["intact"] and status["installed"]["nginx"] is None
    assert status["certificates"] == ["site.crt", "site.key"]
    assert status["running"] is False and status["url"] == "https://localhost:8443"
    assert status["upstream"] == "127.0.0.1:8000" and status["upload_mb"] == 4097


def test_standard_https_port_is_left_out_of_the_url(run_area, store, tmp_path):

    proxy = manager(store, tmp_path)

    assert proxy.url({**pm.DEFAULTS, "port": 443, "address": "ids.example.com"}) == "https://ids.example.com"


# -- real programs, real proxying ----------------------------------------------------------------

class Upstream:
    """A tiny dashboard stand-in: health, header echo, and a body counter."""

    def __init__(self):

        class Handler(BaseHTTPRequestHandler):

            protocol_version = "HTTP/1.1"

            def reply(self, payload):
                body = json.dumps(payload).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):

                if self.path == "/api/healthz":
                    return self.reply({"status": "ok"})

                self.reply({k.lower(): v for k, v in self.headers.items()})

            def do_PUT(self):

                size = 0

                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    while True:
                        line = self.rfile.readline().strip()
                        length = int(line, 16)
                        if length == 0:
                            self.rfile.readline()
                            break
                        size += len(self.rfile.read(length))
                        self.rfile.readline()
                else:
                    remaining = int(self.headers.get("Content-Length", 0))

                    while remaining:
                        chunk = self.rfile.read(min(1 << 20, remaining))
                        size += len(chunk)
                        remaining -= len(chunk)

                self.reply({"bytes": size})

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)

        threading.Thread(target=self.server.serve_forever, daemon=True).start()

        self.address = f"127.0.0.1:{self.server.server_port}"

    def close(self):
        self.server.shutdown()


@pytest.fixture
def upstream():

    up = Upstream()

    yield up

    up.close()


@pytest.fixture(params=[
    pytest.param("caddy", marks=needs_caddy),
    pytest.param("nginx", marks=needs_nginx),
])
def live(request, tmp_path, monkeypatch, upstream):
    """A real proxy of each kind, started by the manager, in front of the stand-in."""

    monkeypatch.setenv("IDS_PROXY_DIR", str(tmp_path / "proxy"))
    monkeypatch.setenv("IDS_PROXY_BIN", str(REAL_BIN))

    store = Store(str(tmp_path / "live.db"))

    proxy = ProxyManager(store, lambda: upstream.address, lambda: 300, lambda: True,
                         cert_dir=str(tmp_path / "certs"))

    proxy.adopt_existing()

    port = free_port()

    proxy.save({"engine": request.param, "port": port})

    proxy.start()

    yield proxy, port, request.param

    proxy.stop()
    store.close()


def secure_connection(port, source=None):

    import http.client
    import ssl

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    return http.client.HTTPSConnection("localhost", port, context=context, source_address=source)


def test_a_real_proxy_starts_serves_https_and_stops(live):

    proxy, port, engine = live

    assert proxy.running() and proxy.pid(engine)

    result = proxy.test()

    assert result["ok"], result
    assert result["tls"] in ("TLSv1.2", "TLSv1.3")
    assert result["dashboard"] == "ok"

    # (HSTS comes from the dashboard itself; this stand-in does not send it)
    assert result["hsts"] is False

    proxy.stop()

    assert not proxy.running() and proxy.pid(engine) is None

    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1).close()


def test_a_real_proxy_tells_the_dashboard_who_the_client_really_is(live):
    """A client's own X-Forwarded-For claim must be replaced, not passed on."""

    proxy, port, engine = live

    conn = secure_connection(port, source=("127.0.0.2", 0))

    conn.request("GET", "/headers", headers={"X-Forwarded-For": "8.8.8.8", "X-Forwarded-Proto": "http"})

    seen = json.loads(conn.getresponse().read())

    assert seen["x-forwarded-for"] == "127.0.0.2", seen
    assert seen["x-forwarded-proto"] == "https"


def test_a_real_proxy_streams_a_large_upload_through(live):

    proxy, port, engine = live

    size = 300 * 1024 * 1024

    conn = secure_connection(port)

    conn.putrequest("PUT", "/sink")
    conn.putheader("Content-Length", str(size))
    conn.endheaders()

    block = b"x" * (1 << 20)

    for _ in range(size // len(block)):
        conn.send(block)

    reply = json.loads(conn.getresponse().read())

    assert reply["bytes"] == size


def test_a_real_proxy_refuses_a_body_over_its_limit(live, tmp_path, monkeypatch):

    proxy, port, engine = live

    # the limit is the dashboard's, in MB: the manager was built with 300
    conn = secure_connection(port)

    conn.putrequest("PUT", "/sink")
    conn.putheader("Content-Length", str(400 * 1024 * 1024))
    conn.endheaders()

    try:
        conn.send(b"x" * (1 << 20))
        reply = conn.getresponse()
        status = reply.status
    except OSError:
        status = "closed"

    # nginx answers 413; Caddy either 413, 499 (its code for an aborted request)
    # or just closes the connection. All of them mean: refused, not forwarded.
    assert status in (413, 499, "closed")


def test_the_server_banner_does_not_reveal_a_version(live):

    proxy, port, engine = live

    conn = secure_connection(port)

    conn.request("GET", "/api/healthz")

    banner = conn.getresponse().getheader("Server") or ""

    assert not any(ch.isdigit() for ch in banner), banner


def test_the_certificate_can_be_read_for_trusting(live):

    proxy, port, engine = live

    found = proxy.certificate()

    assert found["pem"].startswith(b"-----BEGIN CERTIFICATE-----")
    assert len(found["fingerprint"].split(":")) == 32 and found["expires"]


def test_the_log_is_readable(live):

    proxy, port, engine = live

    assert isinstance(proxy.log_tail(20), str)


@needs_nginx
def test_nginx_rejecting_its_configuration_is_explained(tmp_path, monkeypatch, upstream):

    monkeypatch.setenv("IDS_PROXY_DIR", str(tmp_path / "proxy"))
    monkeypatch.setenv("IDS_PROXY_BIN", str(REAL_BIN))

    store = Store(str(tmp_path / "bad.db"))

    try:
        proxy = ProxyManager(store, lambda: upstream.address, lambda: 300, lambda: True,
                             cert_dir=str(tmp_path / "certs"))

        proxy.adopt_existing()

        # certificate files that do not exist: what nginx itself will complain about
        store.set_setting("proxy_config", {**pm.DEFAULTS, "engine": "nginx", "port": free_port(),
                                           "tls": "files", "cert": "nope.crt", "key": "nope.key"})

        with pytest.raises(ProxyError, match="rejected the configuration"):
            proxy.start()

        assert not proxy.running()
    finally:
        store.close()


@needs_caddy
@pytest.mark.parametrize("settings", [
    {},                                                                   # local
    {"address": "ids.example.com", "port": 443, "expose": True, "tls": "me@example.com"},   # public, Let's Encrypt
    {"address": "ids.example.com", "port": 443, "expose": True, "tls": "internal"},
])
def test_real_caddy_accepts_the_configuration_the_panel_generates(settings):
    """`caddy adapt` is Caddy's own parser: a value it rejects would stop the proxy from starting."""

    import subprocess

    env = {**os.environ, **caddy_environment({**pm.DEFAULTS, **settings}, "127.0.0.1:8000", 4097, "D:/data")}

    done = subprocess.run(
        [str(REAL_BIN / ("caddy.exe" if os.name == "nt" else "caddy")), "adapt", "--config", str(pm.HERE / "proxy" / "Caddyfile")],
        capture_output=True, text=True, env=env, timeout=60
    )

    assert done.returncode == 0, done.stderr
