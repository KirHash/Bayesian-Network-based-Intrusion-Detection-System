"""Who gets push notifications, and sending them: the subscriptions and the server's VAPID identity."""
import json
import logging
import os

import webpush

log = logging.getLogger("ids")

SETTING = "push_vapid"

# most devices one person may register (a lost phone's entry is removed when the push service says it is gone)
MAX_DEVICES = 10


class PushService:

    def __init__(self, store, box=None, subject=None, sender=webpush.send):

        self.store = store
        self.box = box
        self.subject = subject or os.environ.get("IDS_PUSH_SUBJECT") or webpush.DEFAULT_SUBJECT
        self.sender = sender

    # -- the server's identity ------------------------------------------------------------------------

    def keys(self):
        """(private PEM, public key). Made on first use and kept, the private half encrypted."""

        stored = self.store.get_setting(SETTING)

        if stored:
            pem = stored["private"]

            return (self.box.decrypt(pem) if self.box else pem), stored["public"]

        pem, public = webpush.new_vapid_key()

        self.store.set_setting(SETTING, {"private": self.box.encrypt(pem) if self.box else pem, "public": public})

        return pem, public

    def public_key(self):

        return self.keys()[1]

    # -- devices -----------------------------------------------------------------------------------------------

    def subscribe(self, username, subscription):
        """Register a browser for a person. Returns how many devices they now have."""

        endpoint, p256dh, auth = webpush.check_subscription(subscription)

        mine = self.store.list_push(username)

        if endpoint not in {s["endpoint"] for s in mine} and len(mine) >= MAX_DEVICES:
            raise webpush.PushError(f"at most {MAX_DEVICES} devices per person: remove one first")

        self.store.add_push(endpoint, username, p256dh, auth)

        return len(self.store.list_push(username))

    def unsubscribe(self, username, endpoint):

        self.store.delete_push(endpoint, username)

        return len(self.store.list_push(username))

    def status(self, username):

        return {"public_key": self.public_key(), "devices": len(self.store.list_push(username))}

    # -- sending ----------------------------------------------------------------------------------------------------

    def notify(self, title, body, url="/", usernames=None, role=None):
        """Push to every registered device (of the named people, or of people with a role).

        Returns {"sent": n, "gone": n, "failed": n}. A device the push service says is gone is forgotten;
        a failure on one device never stops the others.
        """

        # nobody to tell: do not even make the server's key
        if not self.store.list_push():
            return {"sent": 0, "gone": 0, "failed": 0}

        wanted = None

        if role:
            wanted = {u["username"] for u in self.store.list_users() if u["role"] == role and not u["disabled"]}

        if usernames is not None:
            wanted = set(usernames) if wanted is None else wanted & set(usernames)

        pem, public = self.keys()

        payload = json.dumps({"title": title[:100], "body": body[:300], "url": url, "tag": "ids"}).encode()

        counts = {"sent": 0, "gone": 0, "failed": 0}

        for device in self.store.list_push():

            if wanted is not None and device["username"] not in wanted:
                continue

            try:
                result = self.sender(
                    {"endpoint": device["endpoint"], "keys": {"p256dh": device["p256dh"], "auth": device["auth"]}},
                    payload, pem, public, self.subject
                )
            except webpush.PushError as error:
                log.warning("push to %s failed: %s", device["username"], error)
                counts["failed"] += 1
                continue

            if result == "gone":
                self.store.delete_push(device["endpoint"])
                counts["gone"] += 1
            else:
                counts["sent"] += 1

        return counts
