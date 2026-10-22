import ssl
import sqlite3
import threading
import time
import urllib.request

import pytest
import uvicorn

import serve
from serve import (
    accounts_exist, certificate_covers, check, ensure_certificate, fingerprint,
    is_local, make_self_signed
)


# -- where it may listen ---------------------------------------------------------

@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.5"])
def test_loopback_hosts_are_local(host):

    assert is_local(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.5", "::", "example.com"])
def test_other_hosts_are_not(host):

    assert not is_local(host)


def test_only_the_proxy_itself_is_believed_about_client_addresses():
    """X-Forwarded-For from anyone else could fake an address and dodge the login lockout."""

    assert serve.trusted_proxies() == ["127.0.0.1", "::1"]

    assert serve.trusted_proxies(["10.0.0.5"]) == ["127.0.0.1", "::1", "10.0.0.5"]

    # no duplicates, order kept
    assert serve.trusted_proxies(["127.0.0.1", "10.0.0.5", "10.0.0.5"]) == ["127.0.0.1", "::1", "10.0.0.5"]

    assert "*" not in serve.trusted_proxies()


def test_a_proxy_can_be_a_private_network_but_never_something_wide():

    assert serve.trusted_proxies(["172.29.77.0/24"]) == ["127.0.0.1", "::1", "172.29.77.0/24"]

    # a host written as a network is just that host
    assert serve.trusted_proxies(["10.0.0.5/32"]) == ["127.0.0.1", "::1", "10.0.0.5"]

    for bad in ("*", "0.0.0.0/0", "10.0.0.0/7", "::/0", "not-an-address", ""):
        with pytest.raises(ValueError):
            serve.trusted_proxies([bad])


def test_a_bad_proxy_ip_stops_the_server_with_a_clear_message(capsys):

    with pytest.raises(SystemExit) as stop:
        serve.main(["--behind-proxy", "--proxy-ip", "0.0.0.0/0"])

    assert "--proxy-ip" in str(stop.value) and "too wide" in str(stop.value)


def test_local_serving_needs_nothing():

    assert check("127.0.0.1", {}, has_accounts=False) is None


def test_network_serving_needs_a_way_to_sign_in():

    message = check("0.0.0.0", {}, tls=True, has_accounts=False)

    assert "manage_users.py" in message and "IDS_ADMIN_TOKEN" in message

    assert check("0.0.0.0", {"IDS_ADMIN_TOKEN": ""}, tls=True, has_accounts=False)


def test_network_serving_needs_encryption_too():

    message = check("0.0.0.0", {"IDS_ADMIN_TOKEN": "x"}, has_accounts=False)

    assert "plain HTTP" in message and "--behind-proxy" in message


@pytest.mark.parametrize("environ, tls, proxy, accounts", [
    ({"IDS_ADMIN_TOKEN": "x"}, True, False, False),
    ({}, True, False, True),
    ({}, False, True, True),
])
def test_safe_combinations_are_allowed(environ, tls, proxy, accounts):

    assert check("0.0.0.0", environ, tls=tls, behind_proxy=proxy,
                 has_accounts=accounts) is None


def test_accounts_are_looked_up_in_the_database(tmp_path):

    path = str(tmp_path / "ids.db")

    assert accounts_exist(path) is False

    db = sqlite3.connect(path)
    db.execute("CREATE TABLE users (username TEXT)")
    db.commit()

    assert accounts_exist(path) is False

    db.execute("INSERT INTO users VALUES ('root')")
    db.commit()
    db.close()

    assert accounts_exist(path) is True

    assert check("0.0.0.0", {"IDS_DB": path}, tls=True) is None


# -- certificates -------------------------------------------------------------

def test_a_self_signed_certificate_names_the_requested_hosts(tmp_path):

    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"

    make_self_signed(cert, key, ["localhost", "127.0.0.1", "ids.example.com"])

    assert certificate_covers(cert, ["localhost", "127.0.0.1", "ids.example.com"])
    assert not certificate_covers(cert, ["other.example.com"])
    assert not certificate_covers(tmp_path / "missing.pem", ["localhost"])

    assert b"PRIVATE KEY" in key.read_bytes()

    parts = fingerprint(cert).split(":")

    assert len(parts) == 32 and all(len(p) == 2 for p in parts)


def test_an_existing_certificate_is_reused_until_it_no_longer_fits(tmp_path):

    first = ensure_certificate(tmp_path)

    stamp = (tmp_path / "ids-selfsigned.pem").read_bytes()

    assert ensure_certificate(tmp_path) == first
    assert (tmp_path / "ids-selfsigned.pem").read_bytes() == stamp

    # a new name it does not cover: a new certificate
    ensure_certificate(tmp_path, extra_hosts=["new.example.com"])

    assert (tmp_path / "ids-selfsigned.pem").read_bytes() != stamp
    assert certificate_covers(tmp_path / "ids-selfsigned.pem", ["new.example.com"])


def test_a_certificate_close_to_expiry_is_replaced(tmp_path):

    cert, key = tmp_path / "ids-selfsigned.pem", tmp_path / "ids-selfsigned.key"

    make_self_signed(cert, key, serve.default_hosts(), days=5)

    assert not certificate_covers(cert, ["localhost"])

    ensure_certificate(tmp_path)

    assert certificate_covers(cert, ["localhost"])


def test_the_generated_certificate_really_serves_https(tmp_path):
    """A client that trusts the certificate completes a TLS handshake."""

    cert, key = ensure_certificate(tmp_path)

    async def app(scope, receive, send):

        if scope["type"] != "http":
            return

        await send({"type": "http.response.start", "status": 200,
                    "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": b"encrypted hello"})

    config = uvicorn.Config(
        app, host="127.0.0.1", port=0, ssl_certfile=cert, ssl_keyfile=key,
        log_level="error", ws="websockets-sansio"
    )

    server = uvicorn.Server(config)

    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 10

    while not server.started and time.time() < deadline:
        time.sleep(0.05)

    port = server.servers[0].sockets[0].getsockname()[1]

    try:
        trusting = ssl.create_default_context(cafile=cert)

        with urllib.request.urlopen(
            f"https://localhost:{port}/", context=trusting, timeout=10
        ) as response:
            assert response.read() == b"encrypted hello"

        # a client that does not trust it must refuse
        with pytest.raises(Exception, match="CERTIFICATE_VERIFY_FAILED|certificate"):
            urllib.request.urlopen(
                f"https://localhost:{port}/",
                context=ssl.create_default_context(), timeout=10
            )

    finally:
        server.should_exit = True
        thread.join(10)


def test_public_serving_needs_a_way_to_sign_in_even_on_this_machine():

    message = check("127.0.0.1", {}, behind_proxy=True, has_accounts=False, public=True)

    assert message and "publicly" in message and "manage_users.py" in message

    assert check("127.0.0.1", {}, behind_proxy=True, has_accounts=True, public=True) is None
    assert check("127.0.0.1", {"IDS_ADMIN_TOKEN": "t"}, behind_proxy=True, has_accounts=False, public=True) is None

    # a local-only proxy without --public is still fine
    assert check("127.0.0.1", {}, behind_proxy=True, has_accounts=False) is None
