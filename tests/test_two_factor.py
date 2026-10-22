"""Two-factor sign-in, recovery codes, password rules, session control and lockout alerts."""
import base64

import pytest

from accounts import (
    COMMON_PASSWORDS, LOCKOUT_SECONDS, MAX_FAILURES, AccountError, Accounts, Locked, TwoFactorRequired,
    new_recovery_codes, new_totp_secret, otpauth_uri, totp_at, verify_totp
)
from storage import Store

PASSWORD = "correct horse battery"

# the RFC 4226 / 6238 test secret, "12345678901234567890"
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode()


class Clock:

    def __init__(self):
        self.now = 1_700_000_000.0

    def __call__(self):
        return self.now


class Events:

    def __init__(self):
        self.seen = []

    def __call__(self, kind, text):
        self.seen.append((kind, text))


@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "t.db"))

    yield store

    store.close()


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def secured(store, clock):

    events = Events()

    acc = Accounts(store, clock=clock, on_event=events)

    acc.create("root", PASSWORD, "admin")

    acc.events = events

    return acc


def step(clock, extra=0):
    return int(clock() // 30) + extra


def turn_on(acc, clock, name="root"):

    secret, _ = acc.begin_two_factor(name)

    codes = acc.confirm_two_factor(name, totp_at(secret, step(clock)))

    return secret, codes


# -- the codes themselves ---------------------------------------------------------------------------------

def test_codes_match_the_published_test_vectors():

    # RFC 4226 appendix D: HOTP for counters 0, 1, 2
    assert [totp_at(RFC_SECRET, n) for n in (0, 1, 2)] == ["755224", "287082", "359152"]

    # RFC 6238: at t=59 s (step 1) the 8-digit code is 94287082, so the 6-digit one ends the same way
    assert totp_at(RFC_SECRET, 59 // 30) == "287082"
    assert totp_at(RFC_SECRET, 59 // 30, digits=8) == "94287082"


def test_a_code_works_once_within_a_small_window():

    now = 1_000_000 * 30

    code = totp_at(RFC_SECRET, now // 30)

    assert verify_totp(RFC_SECRET, code, now) == now // 30
    assert verify_totp(RFC_SECRET, f" {code[:3]} {code[3:]} ", now) == now // 30     # as typed with a space

    # the last step used is spent
    assert verify_totp(RFC_SECRET, code, now, last_step=now // 30) is None

    # one step of clock drift either way is tolerated, two are not
    assert verify_totp(RFC_SECRET, totp_at(RFC_SECRET, now // 30 - 1), now) == now // 30 - 1
    assert verify_totp(RFC_SECRET, totp_at(RFC_SECRET, now // 30 + 1), now) == now // 30 + 1
    assert verify_totp(RFC_SECRET, totp_at(RFC_SECRET, now // 30 - 2), now) is None

    for bad in ("", "12345", "1234567", "abcdef", None):
        assert verify_totp(RFC_SECRET, bad, now) is None


def test_the_setup_uri_and_the_secrets_are_well_formed():

    secret = new_totp_secret()

    assert len(secret) == 32 and base64.b32decode(secret)      # 160 bits
    assert secret != new_totp_secret()

    uri = otpauth_uri(secret, "alice")

    assert uri.startswith("otpauth://totp/Bayesian%20IDS:alice?secret=") and "period=30" in uri

    codes = new_recovery_codes()

    assert len(codes) == len(set(codes)) == 8 and all(len(c) == 9 and c[4] == "-" for c in codes)


# -- signing in with it ----------------------------------------------------------------------------------------

def test_setup_needs_a_working_code_before_it_takes_effect(secured, clock):

    secret, _ = secured.begin_two_factor("root")

    assert secured.two_factor_status("root") == {"enabled": False, "recovery_left": 0}

    # still just a password until confirmed
    secured.login("root", PASSWORD)

    with pytest.raises(AccountError, match="not right"):
        secured.confirm_two_factor("root", "000000")

    codes = secured.confirm_two_factor("root", totp_at(secret, step(clock)))

    assert len(codes) == 8 and secured.two_factor_status("root") == {"enabled": True, "recovery_left": 8}

    with pytest.raises(AccountError, match="already on"):
        secured.begin_two_factor("root")


def test_with_it_on_a_password_alone_is_not_enough(secured, clock):

    secret, _ = turn_on(secured, clock)

    with pytest.raises(TwoFactorRequired):
        secured.login("root", PASSWORD)

    # the answer for a wrong password does not hint at the second factor
    with pytest.raises(AccountError, match="wrong username or password"):
        secured.login("root", "not the password")

    clock.now += 60

    token, _ = secured.login("root", PASSWORD, code=totp_at(secret, step(clock)))

    assert secured.resolve(token)["username"] == "root"


def test_a_code_cannot_be_used_twice_and_wrong_codes_count_toward_the_lockout(secured, clock):

    secret, _ = turn_on(secured, clock)

    clock.now += 60

    code = totp_at(secret, step(clock))

    secured.login("root", PASSWORD, code=code)

    with pytest.raises(AccountError, match="not right"):
        secured.login("root", PASSWORD, code=code)

    for _ in range(MAX_FAILURES):
        with pytest.raises(AccountError):
            secured.login("root", PASSWORD, code="111111")

    with pytest.raises(Locked):
        secured.login("root", PASSWORD, code=totp_at(secret, step(clock, 1)))


def test_recovery_codes_work_once_each(secured, clock):

    _, recovery = turn_on(secured, clock)

    secured.login("root", PASSWORD, code=recovery[0].upper())

    assert secured.two_factor_status("root")["recovery_left"] == 7

    with pytest.raises(AccountError):
        secured.login("root", PASSWORD, code=recovery[0])

    secured.login("root", PASSWORD, code=recovery[1])

    assert any(kind == "two-factor" and "recovery code was used" in text for kind, text in secured.events.seen)


def test_turning_it_off_lets_a_password_in_again_and_is_reported(secured, clock):

    turn_on(secured, clock)

    secured.disable_two_factor("root")

    assert secured.two_factor_status("root")["enabled"] is False

    secured.login("root", PASSWORD)

    assert [k for k, _ in secured.events.seen].count("two-factor") == 2        # on, then off


def test_the_secret_is_stored_encrypted_when_there_is_a_box(store, clock, tmp_path):

    from secrets_store import SecretBox

    acc = Accounts(store, clock=clock, box=SecretBox(tmp_path / "k.key"))

    acc.create("root", PASSWORD, "admin")

    secret, _ = acc.begin_two_factor("root")

    stored = store.get_user("root")["totp_secret"]

    assert secret not in stored and stored.startswith("enc:")

    acc.confirm_two_factor("root", totp_at(secret, step(clock)))

    clock.now += 60

    acc.login("root", PASSWORD, code=totp_at(secret, step(clock)))


def test_changing_your_password_with_two_factor_on_needs_a_code_and_keeps_you_signed_in(secured, clock):

    secret, _ = turn_on(secured, clock)

    clock.now += 60

    with pytest.raises(TwoFactorRequired):
        secured.change_own("root", PASSWORD, new_password="a different long password")

    token, _ = secured.change_own(
        "root", PASSWORD, new_password="a different long password", code=totp_at(secret, step(clock))
    )

    assert secured.resolve(token)["username"] == "root"


# -- lockout alerts, password rules, sessions ---------------------------------------------------------------------

def test_a_lockout_is_reported_once_per_thing_locked(secured):

    for _ in range(MAX_FAILURES + 3):
        with pytest.raises(AccountError):
            secured.login("root", "wrong password", client="9.9.9.9")

    lockouts = [t for k, t in secured.events.seen if k == "lockout"]

    # the account and the client address each tripped once, and nothing was repeated while locked
    assert len(lockouts) == 2 and any("9.9.9.9" in t for t in lockouts)
    assert all(f"{LOCKOUT_SECONDS // 60} minutes" in t for t in lockouts)


def test_an_event_hook_that_fails_never_breaks_signing_in(store, clock):

    def broken(kind, text):
        raise RuntimeError("the notifier is down")

    acc = Accounts(store, clock=clock, on_event=broken)

    acc.create("root", PASSWORD, "admin")

    for _ in range(MAX_FAILURES):
        with pytest.raises(AccountError):
            acc.login("root", "wrong password")


@pytest.mark.parametrize("password, message", [
    ("password123", "too easy"), ("Password123", "too easy"), ("aaaaaaaaaaaa", "too easy"),
    ("1234567890", "too easy"), ("xx-alice-xx-xx", "contain the username"), ("short", "at least"),
])
def test_weak_passwords_are_refused(store, password, message):

    with pytest.raises(AccountError, match=message):
        Accounts(store).create("alice", password, "admin")

    assert all(len(p) >= 10 for p in COMMON_PASSWORDS)


def test_a_person_sees_their_sessions_and_can_end_all_but_this_one(secured):

    mine, _ = secured.login("root", PASSWORD, client="1.1.1.1")
    other, _ = secured.login("root", PASSWORD, client="2.2.2.2")
    third, _ = secured.login("root", PASSWORD, client="3.3.3.3")

    listed = secured.sessions("root", mine)

    assert len(listed) == 3 and [s["current"] for s in listed].count(True) == 1
    assert {s["client"] for s in listed} == {"1.1.1.1", "2.2.2.2", "3.3.3.3"}
    assert all(len(s["id"]) == 12 for s in listed)

    assert secured.sign_out_others("root", mine) == 2

    assert secured.resolve(mine) and not secured.resolve(other) and not secured.resolve(third)
