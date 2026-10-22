import pytest

import accounts
from accounts import (
    MAX_FAILURES, AccountError, Accounts, Locked, hash_password, verify_password
)
from manage_users import parser, run
from storage import Store

PASSWORD = "correct horse battery"


@pytest.fixture
def store(tmp_path):

    store = Store(str(tmp_path / "a.db"))

    yield store

    store.close()


class Clock:

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def acc(store, clock):

    return Accounts(store, clock=clock)


@pytest.fixture
def admin(acc):

    acc.create("root", PASSWORD, "admin")

    return "root"


# -- passwords -------------------------------------------------------------

def test_passwords_are_salted_and_verified():

    first, second = hash_password(PASSWORD), hash_password(PASSWORD)

    assert first != second
    assert PASSWORD not in first

    assert verify_password(PASSWORD, first) and verify_password(PASSWORD, second)
    assert not verify_password("wrong password!", first)


@pytest.mark.parametrize("stored", ["", "garbage", "bcrypt$x$y", "scrypt$a$b$c$d$e"])
def test_malformed_hashes_never_match_and_never_crash(stored):

    assert verify_password(PASSWORD, stored) is False


# -- creating accounts -------------------------------------------------------

def test_username_and_password_rules(acc):

    for bad in ("", "a", "UPPER space", "-leading", "x" * 40, "semi;colon"):
        with pytest.raises(AccountError, match="usernames"):
            acc.create(bad, PASSWORD, "admin")

    with pytest.raises(AccountError, match="at least"):
        acc.create("root", "short", "admin")

    with pytest.raises(AccountError, match="role"):
        acc.create("root", PASSWORD, "superuser")


def test_usernames_are_case_insensitive_and_unique(acc, admin):

    assert acc.create("  Alice ", PASSWORD, "viewer") == "alice"

    with pytest.raises(AccountError, match="taken"):
        acc.create("ALICE", PASSWORD, "viewer")


def test_the_first_account_must_be_an_admin(acc):

    with pytest.raises(AccountError, match="first account"):
        acc.create("viewer1", PASSWORD, "viewer")

    assert not acc.any_users()

    acc.create("root", PASSWORD, "admin")

    assert acc.any_users()

    acc.create("viewer1", PASSWORD, "viewer")


def test_listing_never_includes_hashes(acc, admin):

    listing = acc.users()

    assert listing[0]["username"] == "root"
    assert "password_hash" not in listing[0]


# -- the last admin ----------------------------------------------------------

def test_the_last_admin_cannot_be_removed_demoted_or_disabled(acc, admin):

    for action in (
        lambda: acc.delete(admin),
        lambda: acc.set_role(admin, "viewer"),
        lambda: acc.set_disabled(admin, True),
    ):
        with pytest.raises(AccountError, match="last enabled admin"):
            action()

    acc.create("second", PASSWORD, "admin")

    acc.set_role(admin, "analyst")

    # now `second` is the last one
    with pytest.raises(AccountError, match="last enabled admin"):
        acc.delete("second")


def test_a_disabled_admin_does_not_count_as_an_admin(acc, admin):

    acc.create("second", PASSWORD, "admin")

    acc.set_disabled("second", True)

    with pytest.raises(AccountError, match="last enabled admin"):
        acc.delete(admin)


# -- sessions -------------------------------------------------------------

def test_login_gives_a_session_that_resolves_to_the_user(acc, admin):

    token, user = acc.login("ROOT", PASSWORD)

    assert user["role"] == "admin"

    assert acc.resolve(token) == {"username": "root", "role": "admin"}
    assert acc.resolve("not-a-token") is None
    assert acc.resolve(None) is None

    assert acc.users()[0]["last_login"]


def test_only_a_hash_of_the_token_is_stored(acc, admin, store):

    token, _ = acc.login("root", PASSWORD)

    rows = store.db.execute("SELECT token_hash FROM sessions").fetchall()

    assert len(rows) == 1 and token not in rows[0][0]


def test_logout_ends_the_session(acc, admin):

    token, _ = acc.login("root", PASSWORD)

    acc.logout(token)

    assert acc.resolve(token) is None


def test_expired_sessions_stop_working(acc, admin, store, monkeypatch):

    token, _ = acc.login("root", PASSWORD)

    store.db.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00'")
    store.db.commit()

    assert acc.resolve(token) is None


def test_role_changes_apply_to_existing_sessions(acc, admin):

    acc.create("second", PASSWORD, "admin")

    token, _ = acc.login("root", PASSWORD)

    acc.set_role("root", "viewer")

    assert acc.resolve(token)["role"] == "viewer"


def test_disabling_or_changing_a_password_ends_sessions(acc, admin):

    acc.create("bob", PASSWORD, "analyst")

    first, _ = acc.login("bob", PASSWORD)

    acc.set_password("bob", "a different password")

    assert acc.resolve(first) is None

    with pytest.raises(AccountError, match="wrong"):
        acc.login("bob", PASSWORD)

    second, _ = acc.login("bob", "a different password")

    acc.set_disabled("bob", True)

    assert acc.resolve(second) is None

    with pytest.raises(AccountError, match="wrong"):
        acc.login("bob", "a different password")


def test_deleting_a_user_ends_their_sessions(acc, admin):

    acc.create("bob", PASSWORD, "viewer")

    token, _ = acc.login("bob", PASSWORD)

    acc.delete("bob")

    assert acc.resolve(token) is None


# -- brute force -----------------------------------------------------------

def test_wrong_passwords_do_not_reveal_whether_the_user_exists(acc, admin):

    for name in ("root", "nobody"):
        with pytest.raises(AccountError) as error:
            acc.login(name, "wrong password!")

        assert str(error.value) == "wrong username or password"


def test_repeated_failures_lock_the_account_then_release_it(acc, admin, clock):

    for _ in range(MAX_FAILURES):
        with pytest.raises(AccountError, match="wrong"):
            acc.login("root", "nope nope nope", client="10.0.0.9")

    # even the right password is refused while locked
    with pytest.raises(Locked) as locked:
        acc.login("root", PASSWORD, client="10.0.0.9")

    assert 0 < locked.value.retry_after <= accounts.LOCKOUT_SECONDS

    clock.now += accounts.LOCKOUT_SECONDS + 1

    token, _ = acc.login("root", PASSWORD, client="10.0.0.9")

    assert acc.resolve(token)


def test_a_client_guessing_many_usernames_is_locked_out_too(acc, admin):

    for i in range(MAX_FAILURES):
        with pytest.raises(AccountError):
            acc.login(f"user{i}", "guess guess guess", client="6.6.6.6")

    with pytest.raises(Locked):
        acc.login("root", PASSWORD, client="6.6.6.6")

    # someone else is unaffected
    assert acc.login("root", PASSWORD, client="1.2.3.4")


def test_a_successful_login_clears_the_failure_count(acc, admin):

    for _ in range(MAX_FAILURES - 1):
        with pytest.raises(AccountError):
            acc.login("root", "nope nope nope", client="a")

    acc.login("root", PASSWORD, client="b")

    for _ in range(MAX_FAILURES - 1):
        with pytest.raises(AccountError, match="wrong"):
            acc.login("root", "nope nope nope", client="c")


# -- the command-line tool ------------------------------------------------

def cli(acc, *argv, password=PASSWORD):

    lines = []

    code = run(parser().parse_args(argv), acc, lambda *a: password, lines.append)

    return code, "\n".join(lines)


def test_cli_creates_lists_and_changes_accounts(acc):

    assert "No accounts yet" in cli(acc, "list")[1]

    assert cli(acc, "add", "root", "--role", "admin")[0] == 0
    assert cli(acc, "add", "kim", "--role", "analyst")[0] == 0

    listing = cli(acc, "list")[1]

    assert "root" in listing and "analyst" in listing and "enabled" in listing

    assert cli(acc, "role", "kim", "viewer")[0] == 0
    assert acc.get("kim")["role"] == "viewer"

    assert cli(acc, "disable", "kim")[0] == 0
    assert acc.get("kim")["disabled"] == 1

    assert cli(acc, "enable", "kim")[0] == 0
    assert cli(acc, "remove", "kim")[0] == 0

    assert [u["username"] for u in acc.users()] == ["root"]


def test_cli_reports_mistakes_with_a_failing_exit_code(acc):

    cli(acc, "add", "root", "--role", "admin")

    code, message = cli(acc, "remove", "root")

    assert code == 1 and "last enabled admin" in message

    code, message = cli(acc, "add", "weak", "--role", "viewer", password="short")

    assert code == 1 and "at least" in message

    assert cli(acc, "passwd", "ghost")[0] == 1


# -- people changing their own sign-in details -----------------------------------------

NEW_PASSWORD = "a different long password"


def test_changing_your_own_password_keeps_you_signed_in_and_ends_the_old_sessions(acc, admin):

    old_token, _ = acc.login("root", PASSWORD)

    token, user = acc.change_own("root", PASSWORD, new_password=NEW_PASSWORD)

    assert user["username"] == "root"
    assert acc.resolve(old_token) is None
    assert acc.resolve(token)["username"] == "root"

    with pytest.raises(AccountError):
        acc.login("root", PASSWORD)

    acc.login("root", NEW_PASSWORD)


def test_renaming_yourself_moves_the_account_and_keeps_its_role(acc, admin):

    acc.create("vera", PASSWORD, "viewer")

    token, user = acc.change_own("vera", PASSWORD, new_username="  Vera.K ")

    assert user["username"] == "vera.k" and user["role"] == "viewer"
    assert acc.resolve(token)["username"] == "vera.k"

    assert acc.get("vera.k")["role"] == "viewer"

    with pytest.raises(AccountError):
        acc.get("vera")

    acc.login("vera.k", PASSWORD)


def test_both_can_change_at_once(acc, admin):

    token, user = acc.change_own("root", PASSWORD, new_username="boss", new_password=NEW_PASSWORD)

    assert user["username"] == "boss"

    acc.login("boss", NEW_PASSWORD)


@pytest.mark.parametrize("kwargs, message", [
    ({"new_password": "short"}, "at least"),
    ({"new_username": "x"}, "usernames are"),
    ({"new_username": "taken"}, "taken"),
    ({}, "nothing to change"),
    ({"new_password": PASSWORD}, "same as the current"),
])
def test_bad_changes_are_refused_and_change_nothing(acc, admin, kwargs, message):

    acc.create("taken", PASSWORD, "viewer")

    with pytest.raises(AccountError, match=message):
        acc.change_own("root", PASSWORD, **kwargs)

    # still signed up as before, with the same password
    acc.login("root", PASSWORD)


def test_a_wrong_current_password_changes_nothing_and_counts_as_a_failed_attempt(acc, admin):

    with pytest.raises(AccountError, match="current password is wrong"):
        acc.change_own("root", "not the password", new_password=NEW_PASSWORD)

    acc.login("root", PASSWORD)

    # guessing the current password is rate limited like signing in
    for _ in range(MAX_FAILURES):
        with pytest.raises(AccountError):
            acc.change_own("root", "guess-guess-guess", new_password=NEW_PASSWORD)

    with pytest.raises(Locked):
        acc.change_own("root", PASSWORD, new_password=NEW_PASSWORD)
