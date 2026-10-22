import hashlib
import io
import json

import pytest

import go_online as go


def test_the_address_is_found_in_cloudflared_output():

    line = "2026-10-21T10:00:00Z INF |  https://relating-monday-boost-pretty.trycloudflare.com  |"

    assert go.tunnel_address(line) == "https://relating-monday-boost-pretty.trycloudflare.com"
    assert go.tunnel_address("INF Requesting new quick Tunnel on trycloudflare.com...") is None


@pytest.mark.parametrize("value, expected", [
    ("https://a.netlify.app", "https://a.netlify.app"),
    ("https://a.netlify.app/", "https://a.netlify.app"),
    ("https://a.netlify.app, https://b.example", "https://a.netlify.app"),
    ("javascript:alert(1)", None), ("https://a/ b", None), ("", None), (None, None),
])
def test_site_origin(value, expected):

    assert go.site_origin(value) == expected


@pytest.mark.parametrize("system, machine, expected", [
    ("Windows", "AMD64", "cloudflared-windows-amd64.exe"),
    ("Linux", "x86_64", "cloudflared-linux-amd64"),
    ("Linux", "aarch64", "cloudflared-linux-arm64"),
    ("Windows", "ARM64", None), ("Darwin", "arm64", None),
])
def test_the_right_download_for_the_system(system, machine, expected):

    assert go.asset_name(system, machine) == expected


def release(content, digest=None):

    digest = digest or "sha256:" + hashlib.sha256(content).hexdigest()

    listing = {"tag_name": "9.9.9", "assets": [
        {"name": "cloudflared-linux-amd64", "digest": digest, "browser_download_url": "https://example/download"}]}

    def opener(url, timeout=60):
        return io.BytesIO(json.dumps(listing).encode() if "api.github" in url else content)

    return opener


@pytest.fixture
def linux_download(monkeypatch):

    monkeypatch.setattr(go, "asset_name", lambda *a: "cloudflared-linux-amd64")


def test_a_download_matching_its_published_hash_is_installed(tmp_path, linux_download):

    path = go.download_cloudflared(tmp_path, opener=release(b"binary"))

    assert open(path, "rb").read() == b"binary"


def test_a_download_that_does_not_match_is_discarded(tmp_path, linux_download):

    with pytest.raises(RuntimeError, match="SHA-256"):
        go.download_cloudflared(tmp_path, opener=release(b"tampered", "sha256:" + "0" * 64))

    assert list(tmp_path.iterdir()) == []


def test_a_release_without_a_hash_is_refused(tmp_path, linux_download):

    with pytest.raises(RuntimeError, match="lists no SHA-256"):
        go.download_cloudflared(tmp_path, opener=release(b"x", digest="none"))


class Reply(io.BytesIO):

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_the_address_is_published_to_duckdns_and_cleared_again():

    seen = []

    def opener(url, timeout=20):
        seen.append(url)
        return Reply(b"OK\nTXT\nUPDATED")

    assert go.duckdns_update("myids.duckdns.org", "tok", "https://a-b.trycloudflare.com", opener)
    assert go.duckdns_update("myids", "tok", "", opener)

    first, second = seen

    assert "domains=myids&" in first and "token=tok" in first and "txt=https%3A%2F%2Fa-b.trycloudflare.com" in first
    assert "clear=true" in second


def test_a_refusal_or_an_outage_is_reported_not_raised():

    assert go.duckdns_update("x", "bad", "t", lambda url, timeout=20: Reply(b"KO")) is False

    def down(url, timeout=20):
        raise OSError("offline")

    assert go.duckdns_update("x", "t", "t", down) is False


def test_the_env_file_is_updated_in_place(tmp_path):

    import setup_online

    path = tmp_path / ".env"

    path.write_text("# a comment\nIDS_DB=mine.db\n# IDS_SITE_URL=https://your-site.netlify.app\n")

    setup_online.update_env_file(path, {"IDS_SITE_URL": "https://x.netlify.app", "DUCKDNS_TOKEN": "t"})

    assert path.read_text().splitlines() == [
        "# a comment", "IDS_DB=mine.db", "IDS_SITE_URL=https://x.netlify.app", "DUCKDNS_TOKEN=t"]

    # and again: replaced, not duplicated
    setup_online.update_env_file(path, {"DUCKDNS_TOKEN": "u"})

    assert path.read_text().count("DUCKDNS_TOKEN") == 1 and "DUCKDNS_TOKEN=u" in path.read_text()


def test_a_failed_check_is_not_taken_for_an_unprotected_server(monkeypatch):

    calls = []

    class Reply(io.BytesIO):

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fetch(url, timeout=60):
        calls.append(url)

        if len(calls) < 3:
            raise OSError("network hiccup")

        return Reply(b'{"required": true}')

    monkeypatch.setattr(go, "fetch", fetch)
    monkeypatch.setattr(go.time, "sleep", lambda s: None)

    assert go.signs_in("https://x", attempts=1) is None
    assert go.signs_in("https://x", attempts=5) is True

    monkeypatch.setattr(go, "fetch", lambda url, timeout=60: Reply(b'{"required": false}'))

    assert go.signs_in("https://x") is False
