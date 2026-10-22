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
import json
import math
import re
import secrets
import struct
import time
from datetime import datetime, timedelta

ROLES = ("viewer", "analyst", "admin")

RANK = {role: i for i, role in enumerate(ROLES)}

MIN_PASSWORD = 10

SESSION_HOURS = 12

MAX_FAILURES = 5

LOCKOUT_SECONDS = 300

# a key that keeps getting locked out is locked for longer each time within a day: 5 min, 15 min, then 45 min
LOCKOUT_GROWTH = 3
LOCKOUT_MAX_STEPS = 2
STRIKE_MEMORY = 86400

USERNAME = re.compile(r"^[a-z0-9][a-z0-9._-]{1,31}$")

SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}

# Passwords people choose by the million. Only ones long enough to pass the length rule are listed.
COMMON_PASSWORDS = {
    "password12", "password123", "password1234", "passw0rd123", "1234567890", "12345678910",
    "123456789012", "qwertyuiop", "qwertyuiop1", "qwerty12345", "1q2w3e4r5t", "iloveyou123",
    "letmein1234", "welcome1234", "administrator", "admin12345", "admin123456", "changeme123",
    "0123456789", "abcdefghij", "abc1234567", "monkey12345", "football123", "baseball123",
    "dragon12345", "master12345", "trustno1234", "sunshine123", "princess123", "superman123"
}

TOTP_STEP = 30

RECOVERY_CODES = 8


def new_totp_secret():
    """A random 160-bit secret in base32, the form authenticator apps take."""

    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def totp_at(secret, step, digits=6):
    """RFC 6238 code for one 30-second step (HMAC-SHA1, the standard apps use)."""

    key = base64.b32decode(secret + "=" * (-len(secret) % 8))

    digest = hmac.new(key, struct.pack(">Q", step), "sha1").digest()

    offset = digest[-1] & 15

    number = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % 10 ** digits

    return f"{number:0{digits}d}"


def verify_totp(secret, code, now, last_step=0, window=1):
    """The step a code belongs to, or None. One step either side tolerates clock drift; a step at or
    before the last accepted one is refused, so a code works once."""

    code = re.sub(r"\s", "", code or "")

    if not re.fullmatch(r"\d{6}", code):
        return None

    step = int(now // TOTP_STEP)

    for candidate in range(step - window, step + window + 1):

        if candidate > last_step and hmac.compare_digest(totp_at(secret, candidate), code):
            return candidate

    return None


def otpauth_uri(secret, username, issuer="Bayesian IDS"):
    """What an authenticator app scans (as a QR code) or imports."""

    from urllib.parse import quote

    return (
        f"otpauth://totp/{quote(issuer)}:{quote(username)}?secret={secret}"
        f"&issuer={quote(issuer)}&algorithm=SHA1&digits=6&period={TOTP_STEP}"
    )


def new_recovery_codes(count=RECOVERY_CODES):
    """One-time codes for a lost phone, like 7k3m-x9qa. Only their hashes are stored."""

    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"

    return [
        "".join(secrets.choice(alphabet) for _ in range(4)) + "-" + "".join(secrets.choice(alphabet) for _ in range(4))
        for _ in range(count)
    ]


class AccountError(ValueError):
    """Something the caller did wrong, with a message fit to show."""


class TwoFactorRequired(AccountError):
    """The password was right; a code from the authenticator app (or a recovery code) is still needed."""

    def __init__(self):

        super().__init__("a two-factor code is required")


class Locked(AccountError):

    def __init__(self, retry_after):

        minutes = max(1, math.ceil(retry_after / 60))

        super().__init__(f"too many failed attempts; try again in {minutes} minute{'s' if minutes != 1 else ''}")

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

    def __init__(self, store, clock=time.time, box=None, on_event=None):

        self.store = store
        self.clock = clock
        self.failures = {}
        self.locks = {}
        self.strikes = {}
        self.signups = {}

        # encrypts the two-factor secrets (a SecretBox); without one they are stored as given
        self.box = box

        # called as on_event(kind, text) for things worth telling an admin about
        self.on_event = on_event

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
    def check_password(password, username=""):

        password = password or ""

        if len(password) < MIN_PASSWORD:
            raise AccountError(
                f"passwords need at least {MIN_PASSWORD} characters"
            )

        plain = password.lower()

        if plain in COMMON_PASSWORDS or len(set(plain)) < 4:
            raise AccountError("that password is too easy to guess: choose something less common")

        name = (username or "").strip().lower()

        if len(name) >= 3 and name in plain:
            raise AccountError("the password must not contain the username")

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

        # never the hash, the (encrypted) two-factor secret or the recovery-code hashes
        hidden = ("password_hash", "totp_secret", "totp_step", "recovery")

        return [
            {**{k: v for k, v in user.items() if k not in hidden}, "two_factor": bool(user["totp_enabled"])}
            for user in self.store.list_users()
        ]

    def create(self, username, password, role):

        username = self.clean_username(username)

        self.check_password(password, username)
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

        self.check_password(password, user["username"])

        self.store.update_user(user["username"], password_hash=hash_password(password))

        # a changed password ends every session of that user
        self.store.delete_sessions(user["username"])

    def rename(self, username, new_name):

        user = self.get(username)

        new_name = self.clean_username(new_name)

        if new_name == user["username"]:
            return new_name

        if self.store.get_user(new_name):
            raise AccountError("that username is taken")

        self.store.rename_user(user["username"], new_name)

        return new_name

    def change_own(self, username, current_password, new_username=None, new_password=None, client="?", code=None):
        """A person changing their own sign-in details.

        The current password is checked first (with the same lockout as signing in).
        Everything is validated before anything is changed, and the person is left
        signed in: a changed password or name ends their sessions, so a fresh one is
        returned as (token, user).
        """

        try:
            token, user = self.login(username, current_password, client, code)
        except (Locked, TwoFactorRequired):
            raise
        except AccountError as error:
            raise AccountError(
                "that code is not right (or was already used)" if "code" in str(error) else "the current password is wrong"
            )

        self.logout(token)

        target = user["username"]

        if new_password is not None:
            self.check_password(new_password, new_username or target)


        if new_username is not None:

            target = self.clean_username(new_username)

            if target != user["username"] and self.store.get_user(target):
                raise AccountError("that username is taken")

        if new_password is None and target == user["username"]:
            raise AccountError("nothing to change")

        if new_password is not None and new_password == current_password:
            raise AccountError("the new password is the same as the current one")

        if target != user["username"]:
            self.rename(user["username"], target)

        if new_password is not None:
            self.set_password(target, new_password)

        # the second factor was just spent proving who is asking; the new session needs no second one
        return self.open_session(target, self.get(target), client)

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

    # -- self-registration --------------------------------------------------

    PENDING = 2

    SIGNUP_PER_HOUR = 5

    def signup_mode(self):
        """"off" (default) or "approval": new accounts wait until an administrator enables them."""

        mode = self.store.get_setting("signup_mode", "off")

        return mode if mode in ("off", "approval") else "off"

    def set_signup_mode(self, mode):

        if mode not in ("off", "approval"):
            raise AccountError("sign-up is either off or needs approval")

        self.store.set_setting("signup_mode", mode)

    def signup_state(self, token_required=False):
        """What the sign-up page may offer: "first", "approval" or "closed"."""

        if not self.any_users():
            return "closed" if token_required else "first"

        return "approval" if self.signup_mode() == "approval" else "closed"

    def signup(self, username, password, client="?", token_required=False):
        """Self-registration. Returns (username, role, pending).

        The very first account becomes the administrator (only while no account exists and no
        admin token is set: otherwise anyone could claim it). After that, sign-up works only
        when an administrator switched it to "approval", and the new account is a viewer that
        cannot sign in until an administrator enables it.
        """

        state = self.signup_state(token_required)

        if state == "closed":
            raise AccountError("sign-up is closed: ask an administrator for an account")

        now = self.clock()

        recent = [t for t in self.signups.get(client, []) if now - t < 3600]

        if len(recent) >= self.SIGNUP_PER_HOUR:
            raise Locked(int(3600 - (now - recent[0])) + 1)

        self.signups[client] = [*recent, now]

        if state == "first":
            self.create(username, password, "admin")

            return self.clean_username(username), "admin", False

        name = self.create(username, password, "viewer")

        self.store.update_user(name, disabled=self.PENDING)

        return name, "viewer", True

    # -- logging in -------------------------------------------------------

    def locked_for(self, key):
        """Seconds left on a lockout, or 0."""

        now = self.clock()

        recent = [t for t in self.failures.get(key, []) if now - t < LOCKOUT_SECONDS]

        self.failures[key] = recent

        longer = self.locks.get(key, 0) - now

        if longer > 0:
            return math.ceil(longer)

        if len(recent) >= MAX_FAILURES:
            return math.ceil(LOCKOUT_SECONDS - (now - recent[0]))

        return 0

    def event(self, kind, text):
        """Tell the owner of the dashboard about something security-relevant (never raises)."""

        if self.on_event:

            try:
                self.on_event(kind, text)
            except Exception:
                pass

    def failed(self, keys, what):
        """Count one failed attempt on each key; the attempt that locks one is reported."""

        now = self.clock()

        for key in keys:

            self.failures.setdefault(key, []).append(now)

            recent = [t for t in self.failures[key] if now - t < LOCKOUT_SECONDS]

            if len(recent) == MAX_FAILURES:

                earlier = [t for t in self.strikes.get(key, []) if now - t < STRIKE_MEMORY]

                self.strikes[key] = [*earlier, now]

                seconds = LOCKOUT_SECONDS * LOCKOUT_GROWTH ** min(len(earlier), LOCKOUT_MAX_STEPS)

                if seconds > LOCKOUT_SECONDS:
                    self.locks[key] = now + seconds

                self.event("lockout", f"{what}: {MAX_FAILURES} failed attempts on {key.replace(':', ' ')}; "
                                      f"locked for {seconds // 60} minutes"
                                      + (f" (lockout number {len(earlier) + 1} today)" if earlier else ""))

        # the tables stay small however many addresses guess
        if len(self.failures) > 10_000:
            for stale in [k for k, v in self.failures.items() if not v or now - v[-1] >= LOCKOUT_SECONDS]:
                del self.failures[stale]

    def login(self, username, password, client="?", code=None):
        """Returns (token, user); raises AccountError, Locked or TwoFactorRequired.

        With two-factor sign-in on, the password alone is not enough: the second step needs a code from
        the authenticator app (each works once) or one of the recovery codes (each works once, ever).
        Wrong codes count as failed attempts, like wrong passwords.
        """

        name = (username or "").strip().lower()

        keys = (f"user:{name}", f"client:{client}")

        wait = max(self.locked_for(key) for key in keys)

        if wait:
            raise Locked(wait)

        user = self.store.get_user(name)

        valid = verify_password(password or "", user["password_hash"] if user else DUMMY_HASH)

        if user and valid and user["disabled"] == self.PENDING:
            raise AccountError("your account is waiting for an administrator to approve it")

        if not (user and valid) or user["disabled"]:

            self.failed(keys, f"sign-in as {name!r} from {client}")

            raise AccountError("wrong username or password")

        if user["totp_enabled"]:

            if not (code or "").strip():
                raise TwoFactorRequired()

            if not self.accept_second_factor(user, code):

                self.failed(keys, f"wrong two-factor code for {name!r} from {client}")

                raise AccountError("that code is not right (or was already used)")

        self.failures.pop(keys[0], None)

        return self.open_session(name, user, client)

    def open_session(self, name, user, client="?"):
        """A fresh session for someone whose credentials were just checked. Returns (token, user)."""

        token = secrets.token_urlsafe(32)

        expires = datetime.now() + timedelta(hours=SESSION_HOURS)

        self.store.add_session(
            hash_token(token), name, expires.isoformat(timespec="seconds"), client
        )

        self.store.update_user(
            name, last_login=datetime.now().isoformat(timespec="seconds")
        )

        return token, {**user, "expires_at": expires.isoformat(timespec="seconds")}

    # -- two-factor sign-in --------------------------------------------------

    def seal(self, text):

        return self.box.encrypt(text) if self.box else text

    def unseal(self, text):

        return self.box.decrypt(text) if self.box else text

    def two_factor_status(self, username):

        user = self.get(username)

        left = len(json.loads(user["recovery"] or "[]"))

        return {"enabled": bool(user["totp_enabled"]), "recovery_left": left if user["totp_enabled"] else 0}

    def begin_two_factor(self, username):
        """Start setting it up: a fresh secret, not active until a code from it is confirmed.
        Returns (secret, uri for a QR code)."""

        user = self.get(username)

        if user["totp_enabled"]:
            raise AccountError("two-factor sign-in is already on")

        secret = new_totp_secret()

        self.store.update_user(user["username"], totp_secret=self.seal(secret), totp_step=0)

        return secret, otpauth_uri(secret, user["username"])

    def confirm_two_factor(self, username, code):
        """Turn it on once a code from the new secret is shown to work. Returns the recovery codes,
        which are shown this one time (only their hashes are kept)."""

        user = self.get(username)

        if user["totp_enabled"] or not user["totp_secret"]:
            raise AccountError("start the setup first")

        step = verify_totp(self.unseal(user["totp_secret"]), code, self.clock())

        if step is None:
            raise AccountError("that code is not right: check the app's clock and try the newest one")

        codes = new_recovery_codes()

        self.store.update_user(
            user["username"], totp_enabled=1, totp_step=step,
            recovery=json.dumps([hash_token(c) for c in codes])
        )

        self.event("two-factor", f"two-factor sign-in turned on for {user['username']!r}")

        return codes

    def disable_two_factor(self, username):

        user = self.get(username)

        self.store.update_user(user["username"], totp_secret=None, totp_enabled=0, totp_step=0, recovery=None)

        self.event("two-factor", f"two-factor sign-in turned off for {user['username']!r}")

    def accept_second_factor(self, user, code):
        """A fresh authenticator code, or an unused recovery code (spent when used)."""

        code = (code or "").strip()

        step = verify_totp(self.unseal(user["totp_secret"]), code, self.clock(), user["totp_step"])

        if step is not None:
            self.store.update_user(user["username"], totp_step=step)
            return True

        hashes = json.loads(user["recovery"] or "[]")

        spent = hash_token(code.lower())

        if spent in hashes:

            hashes.remove(spent)

            self.store.update_user(user["username"], recovery=json.dumps(hashes))

            self.event("two-factor", f"a recovery code was used for {user['username']!r} ({len(hashes)} left)")

            return True

        return False

    # -- a person's own sessions -----------------------------------------------

    def sessions(self, username, current_token=None):
        """Live sessions, with the one making the request marked."""

        mine = hash_token(current_token) if current_token else None

        return [
            {
                "id": row["token_hash"][:12], "created_at": row["created_at"],
                "expires_at": row["expires_at"], "client": row["client"],
                "current": row["token_hash"] == mine
            }
            for row in self.store.list_sessions(self.clean_username(username))
        ]

    def sign_out_others(self, username, current_token):
        """End every session of this person except the one asking. Returns how many ended."""

        return self.store.delete_other_sessions(self.clean_username(username), hash_token(current_token))

    def resolve(self, token):
        """The signed-in user for a session token, or None."""

        if not token:
            return None

        return self.store.get_session(hash_token(token))

    def logout(self, token):

        self.store.delete_session(hash_token(token))
