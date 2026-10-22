"""Web Push: the message format, the server's signed identity, and which services it will send to."""
import base64
import io
import json
import urllib.error

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

import webpush as wp


def unb(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def browser():
    """A browser's side of a subscription: its private key, and the p256dh and auth it hands out."""

    private = ec.generate_private_key(ec.SECP256R1())

    return private, wp.b64u(wp.point(private.public_key())), wp.b64u(b"0123456789abcdef")


def subscription(endpoint="https://fcm.googleapis.com/fcm/send/abc123", keys=None):

    _, p256dh, auth = browser()

    return {"endpoint": endpoint, "keys": keys or {"p256dh": p256dh, "auth": auth}}


# -- the encrypted message ---------------------------------------------------------------------------------

def test_the_rfc_8291_worked_example_is_reproduced_byte_for_byte():
    """Section 5 of the RFC prints every input and the resulting message."""

    as_private = ec.derive_private_key(
        int.from_bytes(unb("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw"), "big"), ec.SECP256R1()
    )

    body = wp.encrypt(
        unb("V2hlbiBJIGdyb3cgdXAsIEkgd2FudCB0byBiZSBhIHdhdGVybWVsb24"),
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4",
        "BTBZMqHH6r4Tts7J_aSIgg",
        salt=unb("DGv6ra1nlYgDCS1FRnbzlw"),
        as_private=as_private
    )

    assert wp.b64u(body) == (
        "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A"
        "_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
    )


def test_what_is_encrypted_for_a_browser_is_readable_by_that_browser_only():

    private, p256dh, auth = browser()

    message = json.dumps({"title": "3 Critical alerts", "body": "DDoS from 10.0.0.1", "url": "/?alert=7"}).encode()

    body = wp.encrypt(message, p256dh, auth)

    assert wp.decrypt(body, private, auth) == message

    # another browser, or the wrong auth secret, gets nothing
    other, _, _ = browser()

    with pytest.raises(Exception):
        wp.decrypt(body, other, auth)

    with pytest.raises(Exception):
        wp.decrypt(body, private, wp.b64u(b"fedcba9876543210"))


def test_every_message_is_encrypted_afresh_and_nothing_readable_is_in_it():

    _, p256dh, auth = browser()

    one, two = wp.encrypt(b"secret text", p256dh, auth), wp.encrypt(b"secret text", p256dh, auth)

    assert one != two and b"secret text" not in one


def test_a_message_too_big_for_a_push_service_is_refused():

    _, p256dh, auth = browser()

    wp.encrypt(b"x" * wp.MAX_PAYLOAD, p256dh, auth)

    with pytest.raises(wp.PushError, match="at most"):
        wp.encrypt(b"x" * (wp.MAX_PAYLOAD + 1), p256dh, auth)


# -- who the server says it is --------------------------------------------------------------------------------

def test_the_server_identity_signs_a_token_the_push_service_can_check():

    pem, public = wp.new_vapid_key()

    token = wp.vapid_token("https://fcm.googleapis.com/fcm/send/abc", pem, "mailto:admin@example.org", now=1_700_000_000)

    header, claims, signature = token.split(".")

    assert json.loads(unb(header)) == {"typ": "JWT", "alg": "ES256"}
    assert json.loads(unb(claims)) == {
        "aud": "https://fcm.googleapis.com", "exp": 1_700_000_000 + 12 * 3600, "sub": "mailto:admin@example.org"
    }

    # anyone holding only the public key can verify it
    raw = unb(signature)

    assert len(raw) == 64

    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), unb(public))

    key.verify(
        encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")),
        f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256())
    )

    # a different key's signature does not verify
    other_pem, _ = wp.new_vapid_key()

    forged = wp.vapid_token("https://fcm.googleapis.com/x", other_pem, now=1_700_000_000).split(".")[2]

    with pytest.raises(Exception):
        key.verify(
            encode_dss_signature(int.from_bytes(unb(forged)[:32], "big"), int.from_bytes(unb(forged)[32:], "big")),
            f"{header}.{claims}".encode(), ec.ECDSA(hashes.SHA256())
        )


def test_the_public_key_has_the_form_browsers_expect():

    _, public = wp.new_vapid_key()

    raw = unb(public)

    assert len(raw) == 65 and raw[0] == 4


# -- subscriptions are checked before anything is sent --------------------------------------------------------------

@pytest.mark.parametrize("endpoint", [
    "https://fcm.googleapis.com/fcm/send/abc",
    "https://updates.push.services.mozilla.com/wpush/v2/abc",
    "https://web.push.apple.com/abc",
    "https://wns2-par02p.notify.windows.com/w/?token=abc",
])
def test_the_push_services_browsers_use_are_accepted(endpoint):

    assert wp.check_subscription(subscription(endpoint))[0] == endpoint


@pytest.mark.parametrize("endpoint", [
    "http://fcm.googleapis.com/fcm/send/abc",                    # not encrypted
    "https://internal.example.com/hook",                          # not a push service: a way to aim the server
    "https://127.0.0.1/fcm/send/abc",
    "https://fcm.googleapis.com.evil.example.com/abc",            # a suffix trick
    "https://evilfcm.googleapis.com/abc",                         # not a subdomain (no dot before it)
    "https://user:pass@fcm.googleapis.com/abc",
    "https://fcm.googleapis.com:8443/abc",
    "https://fcm.googleapis.com/" + "a" * 1100,
    "file:///etc/passwd",
])
def test_anything_else_is_refused(endpoint):

    with pytest.raises(wp.PushError):
        wp.check_subscription(subscription(endpoint))


@pytest.mark.parametrize("value", [
    None, {}, {"endpoint": "https://fcm.googleapis.com/x"}, {"endpoint": "https://fcm.googleapis.com/x", "keys": {}},
    {"endpoint": 5, "keys": {"p256dh": "a", "auth": "b"}},
])
def test_something_that_is_not_a_subscription_is_refused(value):

    with pytest.raises(wp.PushError):
        wp.check_subscription(value)


def test_keys_that_are_not_a_real_point_are_refused():

    good = subscription()

    with pytest.raises(wp.PushError, match="keys|base64"):
        wp.check_subscription({**good, "keys": {**good["keys"], "auth": "short"}})

    with pytest.raises(wp.PushError, match="keys|curve"):
        wp.check_subscription({**good, "keys": {**good["keys"], "p256dh": wp.b64u(b"\x04" + b"\x01" * 64)}})

    with pytest.raises(wp.PushError):
        wp.check_subscription({**good, "keys": {**good["keys"], "p256dh": "!!!"}})


# -- sending ----------------------------------------------------------------------------------------------------------

class Reply(io.BytesIO):

    status = 201

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_a_message_is_sent_with_the_headers_the_push_service_needs():

    private, p256dh, auth = browser()

    pem, public = wp.new_vapid_key()

    seen = {}

    def opener(request, timeout):
        seen.update(url=request.full_url, body=request.data, headers=dict(request.header_items()), method=request.get_method())
        return Reply()

    result = wp.send(
        {"endpoint": "https://fcm.googleapis.com/fcm/send/abc", "keys": {"p256dh": p256dh, "auth": auth}},
        b'{"title":"hello"}', pem, public, ttl=600, opener=opener
    )

    assert result == "sent" and seen["method"] == "POST" and seen["url"].endswith("/fcm/send/abc")

    headers = {k.lower(): v for k, v in seen["headers"].items()}

    assert headers["content-encoding"] == "aes128gcm" and headers["ttl"] == "600" and headers["urgency"] == "high"
    assert headers["authorization"].startswith("vapid t=") and headers["authorization"].endswith(f", k={public}")

    # and what was posted is the encrypted message, readable by the browser
    assert wp.decrypt(seen["body"], private, auth) == b'{"title":"hello"}'


@pytest.mark.parametrize("code, expected", [(404, "gone"), (410, "gone")])
def test_a_browser_that_unsubscribed_is_reported_gone(code, expected):

    _, p256dh, auth = browser()

    pem, public = wp.new_vapid_key()

    def opener(request, timeout):
        raise urllib.error.HTTPError(request.full_url, code, "Gone", {}, None)

    assert wp.send({"endpoint": "https://fcm.googleapis.com/x", "keys": {"p256dh": p256dh, "auth": auth}}, b"x", pem, public, opener=opener) == expected


def test_other_failures_are_errors_not_silence():

    _, p256dh, auth = browser()

    pem, public = wp.new_vapid_key()

    sub = {"endpoint": "https://fcm.googleapis.com/x", "keys": {"p256dh": p256dh, "auth": auth}}

    def rejected(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", {}, None)

    with pytest.raises(wp.PushError, match="403"):
        wp.send(sub, b"x", pem, public, opener=rejected)

    def unreachable(request, timeout):
        raise urllib.error.URLError("no route")

    with pytest.raises(wp.PushError, match="could not reach"):
        wp.send(sub, b"x", pem, public, opener=unreachable)


def test_nothing_is_sent_to_a_service_that_is_not_allowed():

    pem, public = wp.new_vapid_key()

    def opener(request, timeout):
        raise AssertionError("must not be called")

    with pytest.raises(wp.PushError):
        wp.send(subscription("https://internal.example.com/x"), b"x", pem, public, opener=opener)
