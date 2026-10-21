"""
User accounts, roles and login sessions.

Roles, lowest to highest:

    viewer   read everything
    analyst  also handle alerts (status, assignee, notes)
    admin    also run capture, change settings, manage users

Passwords are hashed with scrypt and a per-user salt. A session token is
random, handed out once and stored only as a hash, so a copy of the
database does not give anyone a live session. Repeated wrong passwords
lock the account (and the client address) for a few minutes.
"""
import base64
import hashlib
import hmac
import math
import re
import secrets
import time
from datetime import datetime, timedelta

ROLES = ("viewer", "analyst", "admin")

RANK = {role: i for i, role in enumerate(ROLES)}

MIN_PASSWORD = 10

SESSION_HOURS = 12

MAX_FAILURES = 5

LOCKOUT_SECONDS = 300

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")

SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}


class AccountError(ValueError):
    """Something the caller did wrong, with a message fit to show."""


class Locked(AccountError):

    def __init__(self, retry_after):

        super().__init__("too many failed attempts; try again later")

        self.retry_after = retry_after


def b64(raw):

    return base64.b64encode(raw).decode()


def hash_password(password, params=SCRYPT):

    salt = secrets.token_bytes(16)

    digest = hashlib.scrypt(
        password.encode(), salt=salt, dklen=32, maxmem=2 ** 26, **params
    )

    return "$".join([
        "scrypt", str(params["n"]), str(params["r"]), str(params["p"]),
        b64(salt), b64(digest)
    ])


def verify_password(password, stored):
    """Constant-time check; malformed hashes simply do not match."""

    try:
        scheme, n, r, p, salt, digest = stored.split("$")

        if scheme != "scrypt":
            return False

        expected = base64.b64decode(digest)

        actual = hashlib.scrypt(
            password.encode(), salt=base64.b64decode(salt),
            n=int(n), r=int(r), p=int(p), dklen=len(expected), maxmem=2 ** 26
        )

        return hmac.compare_digest(actual, expected)

    except (ValueError, TypeError):
        return False


def hash_token(token):

    return hashlib.sha256(token.encode()).hexdigest()


# Verified for unknown usernames too, so response time does not reveal
# which usernames exist
DUMMY_HASH = hash_password("not-a-real-password")


class Accounts:

    def __init__(self, store, clock=time.time):

        self.store = store
        self.clock = clock
        self.failures = {}

    # -- validation ------------------------------------------------------

    @staticmethod
    def clean_username(username):

        username = (username or "").strip().lower()

        if not USERNAME.match(username):
            raise AccountError(
                "usernames are 2-32 characters: letters, digits, . _ -"
            )

        return username

    @staticmethod
    def check_password(password):

        if len(password or "") < MIN_PASSWORD:
            raise AccountError(
                f"passwords need at least {MIN_PASSWORD} characters"
            )

    @staticmethod
    def check_role(role):

        if role not in ROLES:
            raise AccountError(f"role must be one of {list(ROLES)}")

    def other_admins(self, username):
        """Enabled admins besides this user."""

        return [
            u for u in self.store.list_users()
            if u["role"] == "admin" and not u["disabled"]
            and u["username"] != username
        ]

    def keep_an_admin(self, username):
        """Refuse a change that would leave nobody able to administer."""

        user = self.store.get_user(username)

        if (
            user and user["role"] == "admin" and not user["disabled"]
            and not self.other_admins(username)
        ):
            raise AccountError("this is the last enabled admin")

    # -- managing users ---------------------------------------------------

    def any_users(self):

        return self.store.count_users() > 0

    def users(self):

        return [
            {k: v for k, v in user.items() if k != "password_hash"}
            for user in self.store.list_users()
        ]

    def create(self, username, password, role):

        username = self.clean_username(username)

        self.check_password(password)
        self.check_role(role)

        if self.store.get_user(username):
            raise AccountError("that username is taken")

        # Once the first account exists everything requires a login, so
        # the first one must be able to manage the rest
        if not self.any_users() and role != "admin":
            raise AccountError("the first account must be an admin")

        self.store.add_user(username, hash_password(password), role)

        return username

    def get(self, username):

        user = self.store.get_user(self.clean_username(username))

        if user is None:
            raise AccountError("no such user")

        return user

    def set_password(self, username, password):

        user = self.get(username)

        self.check_password(password)

        self.store.update_user(user["username"], password_hash=hash_password(password))

        # a changed password ends every session of that user
        self.store.delete_sessions(user["username"])

    def set_role(self, username, role):

        user = self.get(username)

        self.check_role(role)

        if role != "admin":
            self.keep_an_admin(user["username"])

        self.store.update_user(user["username"], role=role)

    def set_disabled(self, username, disabled):

        user = self.get(username)

        if disabled:
            self.keep_an_admin(user["username"])
            self.store.delete_sessions(user["username"])

        self.store.update_user(user["username"], disabled=int(bool(disabled)))

    def delete(self, username):

        user = self.get(username)

        self.keep_an_admin(user["username"])

        self.store.delete_user(user["username"])

    # -- logging in -------------------------------------------------------

    def locked_for(self, key):
        """Seconds left on a lockout, or 0."""

        now = self.clock()

        recent = [t for t in self.failures.get(key, []) if now - t < LOCKOUT_SECONDS]

        self.failures[key] = recent

        if len(recent) >= MAX_FAILURES:
            return math.ceil(LOCKOUT_SECONDS - (now - recent[0]))

        return 0

    def login(self, username, password, client="?"):
        """Returns (token, user); raises AccountError or Locked."""

        name = (username or "").strip().lower()

        keys = (f"user:{name}", f"client:{client}")

        wait = max(self.locked_for(key) for key in keys)

        if wait:
            raise Locked(wait)

        user = self.store.get_user(name)

        valid = verify_password(password or "", user["password_hash"] if user else DUMMY_HASH)

        if not (user and valid) or user["disabled"]:

            now = self.clock()

            for key in keys:
                self.failures.setdefault(key, []).append(now)

            raise AccountError("wrong username or password")

        self.failures.pop(keys[0], None)

        token = secrets.token_urlsafe(32)

        expires = datetime.now() + timedelta(hours=SESSION_HOURS)

        self.store.add_session(
            hash_token(token), name, expires.isoformat(timespec="seconds")
        )

        self.store.update_user(
            name, last_login=datetime.now().isoformat(timespec="seconds")
        )

        return token, {**user, "expires_at": expires.isoformat(timespec="seconds")}

    def resolve(self, token):
        """The signed-in user for a session token, or None."""

        if not token:
            return None

        return self.store.get_session(hash_token(token))

    def logout(self, token):

        self.store.delete_session(hash_token(token))
