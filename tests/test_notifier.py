import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from notifier import DEFAULTS, Notifier, digest, webhook_body
from storage import Store


@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "n.db"))

    yield store

    store.close()


@pytest.fixture
def webhook():
    """A local HTTP server that records every POST body."""

    received = []

    class Handler(BaseHTTPRequestHandler):

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            received.append(json.loads(body))
            self.send_response(500 if self.path == "/fail" else 200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)

    threading.Thread(target=server.serve_forever, daemon=True).start()

    yield f"http://127.0.0.1:{server.server_port}", received

    server.shutdown()


CRLF = chr(13) + chr(10)
LF = chr(10)


@pytest.fixture
def smtp():
    """A minimal SMTP server that stores the messages it is given."""

    import socketserver

    messages = []

    class Handler(socketserver.StreamRequestHandler):

        def reply(self, text):
            self.wfile.write((text + CRLF).encode())

        def handle(self):

            self.reply("220 test")

            data = None

            for raw in self.rfile:

                line = raw.decode().rstrip(CRLF)

                if data is not None:
                    if line == ".":
                        messages.append(LF.join(data))
                        data = None
                        self.reply("250 queued")
                    else:
                        data.append(line)
                    continue

                command = line.split(" ")[0].upper()

                if command in ("EHLO", "HELO"):
                    self.reply("250 test")
                elif command == "DATA":
                    data = []
                    self.reply("354 go ahead")
                elif command == "QUIT":
                    self.reply("221 bye")
                    return
                else:
                    self.reply("250 ok")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)

    threading.Thread(target=server.serve_forever, daemon=True).start()

    yield server.server_address[1], messages

    server.shutdown()
    server.server_close()


def config(**overrides):

    return {**DEFAULTS, **overrides}


def alert(make_alert, **overrides):

    return {**make_alert(**overrides), "id": overrides.get("id", 1)}


def test_digest_summarises_counts_and_worst_alert(make_alert):

    alerts = [
        alert(make_alert, id=1, risk="High", attack_type="DDoS"),
        alert(make_alert, id=2, risk="Critical", attack_type="DDoS",
              probability=99.99),
        alert(make_alert, id=3, risk="High", attack_type="PortScan"),
    ]

    subject, text = digest(alerts, "http://ids.local")

    assert "3 new alert(s)" in subject and "Critical" in subject
    assert "1 Critical, 2 High" in text
    assert "DDoS x2" in text and "PortScan x1" in text
    assert "#2 DDoS 10.0.0.5 -> 10.0.0.9:80" in text
    assert "http://ids.local/?alert=2" in text


def test_webhook_formats():

    assert "content" in webhook_body("discord", "s", "t")
    assert webhook_body("slack", "s", "t") == {"text": "*s*\nt"}
    assert webhook_body("generic", "s", "t") == {"subject": "s", "text": "t"}


def test_only_matching_risk_and_sources_are_queued(store, webhook, make_alert):

    url, _ = webhook

    notifier = Notifier(store, config(
        min_risk="High",
        sources=["capture"],
        webhook={"url": url + "/hook"}
    ))

    notifier.submit([
        alert(make_alert, id=1, risk="Medium"),
        alert(make_alert, id=2, risk="High"),
        alert(make_alert, id=3, risk="Critical", source="replay"),
        alert(make_alert, id=4, risk="Critical"),
    ])

    assert [a["id"] for a in notifier.pending] == [2, 4]


def test_nothing_is_queued_without_a_channel(store, make_alert):

    notifier = Notifier(store, config())

    notifier.submit([alert(make_alert, risk="Critical")])

    assert notifier.pending == []
    assert notifier.channels() == []


def test_digest_is_delivered_and_logged(store, webhook, make_alert):

    url, received = webhook

    notifier = Notifier(store, config(
        webhook={"url": url + "/hook", "format": "slack"}
    ))

    alerts = [alert(make_alert, id=i) for i in range(1, 4)]

    result = notifier.send(alerts)

    assert result == {"webhook": {"ok": True}}

    # one message for the whole batch, not three
    assert len(received) == 1
    assert "3 new alert(s)" in received[0]["text"]

    log = store.recent_notifications()

    assert (log[0]["channel"], log[0]["ok"], log[0]["alerts"]) == ("webhook", 1, 3)


def test_failures_are_reported_and_logged(store, webhook, make_alert):

    url, _ = webhook

    notifier = Notifier(store, config(webhook={"url": url + "/fail"}))

    result = notifier.send([alert(make_alert)])

    assert result["webhook"]["ok"] is False
    assert "500" in result["webhook"]["error"]

    assert store.recent_notifications()[0]["ok"] == 0


def test_test_message_does_not_need_alerts(store, webhook):

    url, received = webhook

    notifier = Notifier(store, config(webhook={"url": url + "/hook"}))

    assert notifier.send([], test=True) == {"webhook": {"ok": True}}
    assert "test notification" in received[0]["text"]


def test_status_hides_secrets(store):

    notifier = Notifier(store, config(
        webhook={"url": "https://hooks.example/SECRET", "format": "slack"},
        email={"host": "smtp", "to": ["a@b.c"], "password_env": "X"}
    ))

    shown = json.dumps(notifier.status())

    assert "SECRET" not in shown
    assert notifier.status()["channels"] == ["webhook", "email"]


def test_email_digest_is_delivered(store, smtp, make_alert):

    port, messages = smtp

    notifier = Notifier(store, config(email={
        "host": "127.0.0.1", "port": port, "starttls": False,
        "from": "ids@example.com", "to": ["soc@example.com", "lead@example.com"]
    }))

    result = notifier.send([alert(make_alert, id=7, risk="Critical")])

    assert result == {"email": {"ok": True}}

    assert len(messages) == 1

    assert "Subject: [IDS] 1 new alert(s), worst: Critical" in messages[0]
    assert "To: soc@example.com, lead@example.com" in messages[0]
    assert "Most severe: #7 DDoS" in messages[0]


def test_unreachable_mail_server_is_reported_not_raised(store, make_alert):

    notifier = Notifier(store, config(email={
        "host": "127.0.0.1", "port": 1, "starttls": False,
        "from": "a@b.c", "to": ["d@e.f"]
    }))

    result = notifier.send([alert(make_alert)])

    assert result["email"]["ok"] is False

    assert store.recent_notifications()[0]["ok"] == 0


def test_config_path_comes_from_the_environment(tmp_path, monkeypatch):

    from notifier import load_config

    path = tmp_path / "custom.json"

    path.write_text(json.dumps({"min_risk": "Critical"}))

    monkeypatch.setenv("IDS_NOTIFY_CONFIG", str(path))

    assert load_config()["min_risk"] == "Critical"

    monkeypatch.setenv("IDS_NOTIFY_CONFIG", str(tmp_path / "missing.json"))

    assert load_config()["min_risk"] == DEFAULTS["min_risk"]
