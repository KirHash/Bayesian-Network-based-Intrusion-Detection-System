"""A sign-in key that keeps getting locked out waits longer each time."""
import pytest

import accounts
from accounts import MAX_FAILURES, AccountError, Accounts, Locked
from storage import Store

PASSWORD = "correct horse battery"


class Clock:

    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def acc(tmp_path, clock):

    store = Store(str(tmp_path / "a.db"))

    acc = Accounts(store, clock=clock)

    acc.create("root", PASSWORD, "admin")

    yield acc

    store.close()


def lock_out(acc, client):

    for _ in range(MAX_FAILURES):
        with pytest.raises(AccountError):
            acc.login("root", "nope nope nope", client=client)

    with pytest.raises(Locked) as locked:
        acc.login("root", PASSWORD, client=client)

    return locked.value


def test_a_key_that_keeps_getting_locked_out_waits_longer_each_time(acc, clock):

    waits = []

    for _ in range(4):

        error = lock_out(acc, "7.7.7.7")

        waits.append(error.retry_after)

        clock.now += error.retry_after + 1

    base = accounts.LOCKOUT_SECONDS

    # 5 minutes, then 15, then 45, and 45 is the most
    assert waits[0] <= base
    assert base < waits[1] <= base * 3
    assert base * 3 < waits[2] <= base * 9
    assert base * 3 < waits[3] <= base * 9


def test_the_lockout_message_says_how_long(acc):

    error = lock_out(acc, "8.8.8.8")

    assert "try again in 5 minutes" in str(error)


def test_a_longer_lockout_is_reported_to_the_administrator(tmp_path, clock):

    events = []

    store = Store(str(tmp_path / "b.db"))

    acc = Accounts(store, clock=clock, on_event=lambda kind, text: events.append(text))

    acc.create("root", PASSWORD, "admin")

    for _ in range(2):
        error = lock_out(acc, "5.5.5.5")
        clock.now += error.retry_after + 1

    assert any("locked for 5 minutes" in text for text in events)
    assert any("locked for 15 minutes" in text and "lockout number 2" in text for text in events)

    store.close()


def test_a_quiet_day_forgets_earlier_lockouts(acc, clock):

    first = lock_out(acc, "4.4.4.4")

    clock.now += accounts.STRIKE_MEMORY + 10

    again = lock_out(acc, "4.4.4.4")

    assert again.retry_after <= accounts.LOCKOUT_SECONDS
    assert first.retry_after <= accounts.LOCKOUT_SECONDS
