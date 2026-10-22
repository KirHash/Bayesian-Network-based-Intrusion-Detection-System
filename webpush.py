"""
Web Push: a notification on a phone or computer that arrives even when the dashboard is closed.

Three standards, implemented here with the `cryptography` package only (no extra dependency):

* RFC 8291 and 8188: the message is encrypted for one browser (ECDH P-256, HKDF, AES-128-GCM), so the
  push service that carries it cannot read it.
* RFC 8292 (VAPID): the server proves who it is with a signed token and a public key that the browser
  registered with when it subscribed.
* RFC 8030: the encrypted message is an HTTPS POST to the address the browser gave out.

The browser's address (the "endpoint") is chosen by whoever subscribes, so the server only posts to the
push services browsers really use (see PUSH_HOSTS): otherwise a subscription could aim the server at any
address.
"""
import base64
import json
import os
import struct
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# the push services of Chrome and Edge (Google, Microsoft), Firefox, and Safari
PUSH_HOSTS = (
    "fcm.googleapis.com",
    "android.googleapis.com",
    "push.services.mozilla.com",
    "push.apple.com",
    "notify.windows.com",
)

RECORD_SIZE = 4096

# push services accept about 4 KB; leave room for the header, padding byte and tag
MAX_PAYLOAD = 3500

DEFAULT_SUBJECT = "mailto:admin@example.invalid"


class PushError(ValueError):
    """Something wrong with a subscription or a message, with a message fit to show."""


def b64u(data):

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text):

    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (ValueError, TypeError):
        raise PushError("not valid base64")


def point(public_key):
    """A public key as the 65 bytes browsers exchange (uncompressed point)."""

    return public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def hkdf(length, salt, info, secret):

    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def check_subscription(subscription):
    """The (endpoint, p256dh, auth) of a browser's PushSubscription, or PushError."""

    try:
        endpoint = subscription["endpoint"]
        p256dh = subscription["keys"]["p256dh"]
        auth = subscription["keys"]["auth"]
    except (KeyError, TypeError):
        raise PushError("that is not a push subscription")

    if not all(isinstance(x, str) for x in (endpoint, p256dh, auth)):
        raise PushError("that is not a push subscription")

    parts = urlsplit(endpoint)

    host = (parts.hostname or "").lower()

    if (
        parts.scheme != "https" or parts.username or parts.password or parts.port not in (None, 443)
        or not any(host == h or host.endswith("." + h) for h in PUSH_HOSTS) or len(endpoint) > 1000
    ):
        raise PushError("that push service is not one this server sends to")

    key = unb64u(p256dh)

    if len(key) != 65 or key[0] != 4 or len(unb64u(auth)) != 16:
        raise PushError("the subscription's keys are not valid")

    try:
        ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), key)
    except ValueError:
        raise PushError("the subscription's key is not a point on the curve")

    return endpoint, p256dh, auth


def encrypt(payload, p256dh, auth, salt=None, as_private=None):
    """The body of a push message: `payload` encrypted for one browser (RFC 8291, one record)."""

    if len(payload) > MAX_PAYLOAD:
        raise PushError(f"a push message holds at most {MAX_PAYLOAD} bytes")

    ua_public = unb64u(p256dh)

    as_private = as_private or ec.generate_private_key(ec.SECP256R1())

    as_public = point(as_private.public_key())

    shared = as_private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public))

    ikm = hkdf(32, unb64u(auth), b"WebPush: info\x00" + ua_public + as_public, shared)

    salt = salt or os.urandom(16)

    key = hkdf(16, salt, b"Content-Encoding: aes128gcm\x00", ikm)
    nonce = hkdf(12, salt, b"Content-Encoding: nonce\x00", ikm)

    # 0x02 closes the last (here the only) record
    sealed = AESGCM(key).encrypt(nonce, payload + b"\x02", None)

    return salt + struct.pack(">I", RECORD_SIZE) + bytes([len(as_public)]) + as_public + sealed


def decrypt(body, ua_private, auth):
    """What a browser does with a message (used by the tests to prove the format)."""

    salt, size, length = body[:16], struct.unpack(">I", body[16:20])[0], body[20]

    as_public, sealed = body[21:21 + length], body[21 + length:]

    ua_public = point(ua_private.public_key())

    shared = ua_private.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))

    ikm = hkdf(32, unb64u(auth), b"WebPush: info\x00" + ua_public + as_public, shared)

    key = hkdf(16, salt, b"Content-Encoding: aes128gcm\x00", ikm)
    nonce = hkdf(12, salt, b"Content-Encoding: nonce\x00", ikm)

    plain = AESGCM(key).decrypt(nonce, sealed, None).rstrip(b"\x00")

    if plain[-1:] != b"\x02":
        raise PushError("the message does not end with the last-record marker")

    return plain[:-1]


# -- the server's identity (VAPID) -------------------------------------------------------------------------

def new_vapid_key():
    """(private key as PEM text, public key as the base64url browsers want)."""

    private = ec.generate_private_key(ec.SECP256R1())

    pem = private.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()

    return pem, b64u(point(private.public_key()))


def vapid_token(endpoint, private_pem, subject=DEFAULT_SUBJECT, now=None, lifetime=12 * 3600):
    """The signed token that proves this server to the push service (RFC 8292, ES256)."""

    parts = urlsplit(endpoint)

    claims = {
        "aud": f"{parts.scheme}://{parts.netloc}",
        "exp": int(now if now is not None else time.time()) + lifetime,
        "sub": subject
    }

    signing = (
        b64u(json.dumps({"typ": "JWT", "alg": "ES256"}, separators=(",", ":")).encode())
        + "." + b64u(json.dumps(claims, separators=(",", ":")).encode())
    )

    private = serialization.load_pem_private_key(private_pem.encode(), password=None)

    r, s = decode_dss_signature(private.sign(signing.encode(), ec.ECDSA(hashes.SHA256())))

    return signing + "." + b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def send(subscription, payload, private_pem, public_b64u, subject=DEFAULT_SUBJECT, ttl=3600, urgency="high", timeout=15, opener=None):
    """Push one message. Returns "sent", "gone" (the browser unsubscribed: forget it) or raises PushError."""

    endpoint, p256dh, auth = check_subscription(subscription)

    body = encrypt(payload, p256dh, auth)

    request = urllib.request.Request(
        endpoint, data=body, method="POST",
        headers={
            "Content-Encoding": "aes128gcm",
            "Content-Type": "application/octet-stream",
            "TTL": str(ttl),
            "Urgency": urgency,
            "Authorization": f"vapid t={vapid_token(endpoint, private_pem, subject)}, k={public_b64u}"
        }
    )

    try:
        with (opener or urllib.request.urlopen)(request, timeout=timeout) as response:
            return "sent" if response.status in (200, 201, 202) else f"status {response.status}"
    except urllib.error.HTTPError as error:

        if error.code in (404, 410):
            return "gone"

        raise PushError(f"the push service answered {error.code}")
    except (urllib.error.URLError, OSError) as error:
        raise PushError(f"could not reach the push service: {error}")
