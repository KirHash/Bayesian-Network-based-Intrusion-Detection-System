"""
Alert notifications: webhook (Slack, Discord, Teams, generic JSON) and
email.

During an attack the IDS can raise hundreds of alerts a second, so
alerts are not sent one by one. Matching alerts are collected for a
short window and sent as one digest per channel.

Configuration lives in notify.json (see notify.example.json); secrets
are read from environment variables named in the config, never stored
in the file.
"""
import asyncio
import json
import logging
import os
import re
import smtplib
import urllib.request
from collections import Counter
from email.message import EmailMessage
from pathlib import Path

RISK_ORDER = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

DEFAULTS = {
    "min_risk": "High",
    # Demo replay traffic would page people for nothing
    "sources": ["capture", "api"],
    "window_seconds": 10,
    "base_url": "http://127.0.0.1:8000",
    "webhook": None,
    "email": None
}

def load_config(path=None):
    """notify.json (or $IDS_NOTIFY_CONFIG) over the defaults."""

    path = path or os.environ.get("IDS_NOTIFY_CONFIG", "notify.json")

    config = dict(DEFAULTS)

    if Path(path).exists():
        config.update(json.loads(Path(path).read_text()))

    return config


def digest(alerts, base_url, test=False):
    """(subject, text) summarising a batch of alert records."""

    if test:
        return (
            "[IDS] test notification",
            "This is a test notification from the Bayesian IDS. "
            "If you can read this, alerting works."
        )

    by_type = {}

    for alert in alerts:
        by_type.setdefault(alert["attack_type"], Counter())[alert["risk"]] += 1

    risks = Counter(a["risk"] for a in alerts)

    worst = max(alerts, key=lambda a: (RISK_ORDER[a["risk"]], a["probability"]))

    headline = ", ".join(
        f"{n} {level}"
        for level, n in sorted(
            risks.items(), key=lambda kv: -RISK_ORDER[kv[0]]
        )
    )

    lines = [f"{len(alerts)} new alert(s): {headline}"]

    for attack_type, counts in sorted(
        by_type.items(), key=lambda kv: -sum(kv[1].values())
    ):
        detail = ", ".join(f"{n} {level}" for level, n in counts.items())
        lines.append(f"  - {attack_type} x{sum(counts.values())} ({detail})")

    where = ""

    if worst.get("src_ip"):
        where = f" {worst['src_ip']} -> {worst.get('dst_ip')}"

        if worst.get("dst_port") is not None:
            where += f":{worst['dst_port']}"

    lines.append(
        f"Most severe: #{worst['id']} {worst['attack_type']}{where} "
        f"({worst['risk']}, {worst['probability']}%)"
    )

    lines.append(f"{base_url}/?alert={worst['id']}")

    return f"[IDS] {len(alerts)} new alert(s), worst: {worst['risk']}", "\n".join(lines)


def webhook_body(kind, subject, text):
    """JSON payload for the webhook flavour."""

    if kind == "discord":
        return {"content": f"**{subject}**\n{text}"}

    if kind in ("slack", "teams", "mattermost"):
        return {"text": f"*{subject}*\n{text}"}

    return {"subject": subject, "text": text}


def send_webhook(config, subject, text):

    body = json.dumps(
        webhook_body(config.get("format", "generic"), subject, text)
    ).encode()

    request = urllib.request.Request(
        config["url"],
        data=body,
        headers={"Content-Type": "application/json"}
    )

    with urllib.request.urlopen(request, timeout=10) as response:
        response.read()


def send_email(config, subject, text):

    message = EmailMessage()

    message["Subject"] = subject
    message["From"] = config["from"]
    message["To"] = ", ".join(config["to"])
    message.set_content(text)

    password = config.get("password") or os.environ.get(
        config.get("password_env", ""), None
    )

    with smtplib.SMTP(config["host"], config.get("port", 587), timeout=15) as smtp:

        if config.get("starttls", True):
            smtp.starttls()

        if config.get("username"):
            smtp.login(config["username"], password or "")

        smtp.send_message(message)


FORMATS = ("slack", "discord", "teams", "mattermost", "generic")

LEVELS = ("Medium", "High", "Critical")

SOURCES = ("capture", "api", "replay")

SETTING = "notify_config"

log = logging.getLogger("ids")

UNREADABLE = (
    "The saved webhook URL / email password cannot be read: the key file next "
    "to the database is missing or does not belong to this data (for example a "
    "backup restored without it). Notifications are off until you enter them "
    "again and press Save."
)


class SettingsError(ValueError):
    """The notification settings are not acceptable; the message says why."""


def valid_url(url):

    return isinstance(url, str) and re.match(r"^https?://[^\s/]+", url) is not None


def valid_address(address):

    return isinstance(address, str) and re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", address) is not None


def build_settings(incoming, previous, box):
    """
    Check what the dashboard sent and produce what is stored: secrets
    encrypted, and a secret left out (None) keeps the stored one.
    """

    previous = previous or {}

    level = incoming.get("min_risk", "High")

    if level not in LEVELS:
        raise SettingsError(f"min_risk must be one of {list(LEVELS)}")

    sources = list(incoming.get("sources", []))

    if not sources or any(s not in SOURCES for s in sources):
        raise SettingsError(f"sources must be some of {list(SOURCES)}")

    window = incoming.get("window_seconds", 10)

    if not isinstance(window, int) or not 1 <= window <= 3600:
        raise SettingsError("the digest window must be 1 to 3600 seconds")

    base_url = incoming.get("base_url") or DEFAULTS["base_url"]

    if not valid_url(base_url):
        raise SettingsError("the dashboard address must start with http:// or https://")

    settings = {
        "min_risk": level, "sources": sources, "window_seconds": window,
        "base_url": base_url.rstrip("/"), "webhook": None, "email": None
    }

    hook = incoming.get("webhook") or {}

    if hook.get("enabled"):

        if hook.get("format", "generic") not in FORMATS:
            raise SettingsError(f"webhook format must be one of {list(FORMATS)}")

        url = hook.get("url")

        old = (previous.get("webhook") or {}).get("url")

        if url is None and not old:
            raise SettingsError("the webhook needs a URL")

        if url is not None and not valid_url(url):
            raise SettingsError("the webhook URL must start with http:// or https://")

        settings["webhook"] = {
            "format": hook.get("format", "generic"),
            "url": box.encrypt(url) if url else old
        }

    mail = incoming.get("email") or {}

    if mail.get("enabled"):

        if not mail.get("host"):
            raise SettingsError("email needs an SMTP server")

        port = mail.get("port", 587)

        if not isinstance(port, int) or not 1 <= port <= 65535:
            raise SettingsError("the SMTP port must be 1 to 65535")

        recipients = list(mail.get("to", []))

        if not recipients or len(recipients) > 20 or not all(map(valid_address, recipients)):
            raise SettingsError("email needs 1 to 20 valid recipient addresses")

        if not valid_address(mail.get("from")):
            raise SettingsError("email needs a valid sender address")

        password = mail.get("password")

        old = (previous.get("email") or {}).get("password")

        settings["email"] = {
            "host": mail["host"], "port": port,
            "starttls": bool(mail.get("starttls", True)),
            "username": mail.get("username") or "",
            "password": box.encrypt(password) if password else (None if password == "" else old),
            "from": mail["from"], "to": recipients
        }

    return settings


def masked(settings):
    """What the dashboard may see: no secrets, only whether they are set."""

    if not settings:
        return None

    hook = settings.get("webhook")

    mail = settings.get("email")

    host = re.match(r"^https?://[^/]+", (hook or {}).get("url", "") or "")

    return {
        "min_risk": settings["min_risk"], "sources": settings["sources"],
        "window_seconds": settings["window_seconds"], "base_url": settings["base_url"],
        "webhook": hook and {
            "enabled": True, "format": hook["format"], "has_url": True,
            "url_hint": "set"
        },
        "email": mail and {
            "enabled": True, "host": mail["host"], "port": mail["port"],
            "starttls": mail["starttls"], "username": mail["username"],
            "has_password": bool(mail.get("password")),
            "from": mail["from"], "to": mail["to"]
        }
    }


def runtime_config(settings, box):
    """Stored settings with secrets decrypted, in the shape the senders use."""

    config = {k: settings[k] for k in ("min_risk", "sources", "window_seconds", "base_url")}

    hook = settings.get("webhook")

    mail = settings.get("email")

    config["webhook"] = hook and {"format": hook["format"], "url": box.decrypt(hook["url"])}

    config["email"] = mail and {
        **{k: mail[k] for k in ("host", "port", "starttls", "username", "from", "to")},
        "password": box.decrypt(mail["password"]) if mail.get("password") else None
    }

    return config


class Notifier:

    def __init__(self, store, config=None, box=None):

        self.store = store

        self.box = box

        self.managed = False

        # set when saved settings exist but their secrets cannot be decrypted
        self.problem = None

        self.config = config if config is not None else load_config()

        if config is None and box is not None:
            self.load_managed()

        self.pending = []

        self.task = None

    def load_managed(self):
        """Use the settings saved from the dashboard, if there are any."""

        stored = self.store.get_setting(SETTING)

        self.problem = None

        if stored and self.box is not None:

            self.managed = True

            try:
                self.config = {**DEFAULTS, **runtime_config(stored, self.box)}
            except ValueError:

                # Better a running server with notifications off than one that
                # will not start: say what is wrong and let the admin fix it
                self.config = dict(DEFAULTS)
                self.problem = UNREADABLE

                log.error("saved notification secrets cannot be decrypted; notifications are off")

        return self.managed

    def save_managed(self, incoming):
        """Validate and store settings from the dashboard, and start using them."""

        previous = self.store.get_setting(SETTING)

        settings = build_settings(incoming, previous, self.box)

        # A secret left blank keeps the stored one; refuse if that one is unreadable
        try:
            runtime_config(settings, self.box)
        except ValueError:
            raise SettingsError(
                "a saved secret can no longer be read: enter the webhook URL "
                "and the email password again"
            )

        self.store.set_setting(SETTING, settings)

        self.load_managed()

        return masked(settings)

    def settings(self):
        """Dashboard view of the settings, and where they come from."""

        stored = self.store.get_setting(SETTING)

        if stored:
            return {
                "source": "dashboard", "problem": self.problem,
                "settings": masked(stored)
            }

        return {
            "source": "file" if self.channels() else "none",
            "settings": None
        }

    def reload(self):
        """Re-read the settings: the dashboard's if saved, else notify.json
        (raises if it is not valid JSON)."""

        if not self.load_managed():
            self.config = load_config()
            self.managed = False

    # -- status ----------------------------------------------------------

    def channels(self):

        return [
            name for name in ("webhook", "email") if self.config.get(name)
        ]

    def status(self):
        """Settings safe to show in the UI (no secrets)."""

        webhook = self.config.get("webhook")

        email = self.config.get("email")

        return {
            "problem": self.problem,
            "source": (
                "dashboard" if self.managed
                else "file" if self.channels() else "none"
            ),
            "channels": self.channels(),
            "min_risk": self.config["min_risk"],
            "sources": self.config["sources"],
            "window_seconds": self.config["window_seconds"],
            "webhook": (
                {"format": webhook.get("format", "generic")}
                if webhook else None
            ),
            "email": {"to": email["to"]} if email else None,
            "recent": self.store.recent_notifications()
        }

    # -- queueing ---------------------------------------------------------

    def submit(self, alerts):
        """Queue alerts that match the configured risk and sources."""

        if not self.channels():
            return

        floor = RISK_ORDER[self.config["min_risk"]]

        self.pending += [
            a for a in alerts
            if a["source"] in self.config["sources"]
            and RISK_ORDER[a["risk"]] >= floor
        ]

    def start(self):

        self.task = asyncio.create_task(self.loop())

    def stop(self):

        if self.task:
            self.task.cancel()

    async def loop(self):

        while True:

            await asyncio.sleep(self.config["window_seconds"])

            if self.pending:

                batch, self.pending = self.pending, []

                await asyncio.to_thread(self.send, batch)

    # -- sending ----------------------------------------------------------

    def send(self, alerts, test=False):
        """Send one digest on every channel; returns per-channel results."""

        subject, text = digest(alerts, self.config["base_url"], test=test)

        results = {}

        for channel, sender in (
            ("webhook", send_webhook), ("email", send_email)
        ):

            settings = self.config.get(channel)

            if not settings:
                continue

            try:
                sender(settings, subject, text)
                results[channel] = {"ok": True}
                self.store.log_notification(channel, True, len(alerts))

            except Exception as error:
                results[channel] = {"ok": False, "error": str(error)}
                self.store.log_notification(
                    channel, False, len(alerts), str(error)
                )

        return results
