"""
Start the server.

    python serve.py                                   # http://127.0.0.1:8000, this machine only
    python serve.py --self-signed                     # https://127.0.0.1:8000 with a generated certificate
    python serve.py --host 0.0.0.0 --cert c.pem --key k.pem
    python serve.py --host 0.0.0.0 --behind-proxy     # a reverse proxy terminates TLS

The dashboard can start packet capture and change settings, so serving it
beyond this machine is refused unless

  * people must sign in (accounts created with manage_users.py, or
    IDS_ADMIN_TOKEN set), and
  * the connection is encrypted: --cert/--key, --self-signed, or
    --behind-proxy to say that a proxy in front already does it.

A self-signed certificate encrypts but browsers will warn about it until
you trust it; the SHA-256 fingerprint is printed so you can check it.
Use a certificate from a real authority (or Let's Encrypt via a proxy)
for anything other people use.
"""
import argparse
import datetime
import ipaddress
import os
import socket
import sqlite3
import sys
from pathlib import Path

import uvicorn

import envfile
import lifecycle

CERT_DIR = "certs"

RENEW_WITHIN_DAYS = 30


def is_local(host):
    """True for loopback addresses and "localhost"."""

    if host == "localhost":
        return True

    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def accounts_exist(db_path):
    """Whether the database already has dashboard accounts."""

    if not Path(db_path).exists():
        return False

    try:
        db = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)

        try:
            return db.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None
        finally:
            db.close()

    except sqlite3.Error:
        return False


def proxy_address(text):
    """One trusted proxy: an address (10.0.0.5) or a private network (172.29.77.0/24).

    A network is how a proxy in another container is trusted, since its address is not fixed.
    "*" and networks so wide that they include strangers are refused: whoever is trusted can
    claim any client address and slip past per-address protections such as the login lockout.
    """

    try:
        network = ipaddress.ip_network(str(text).strip(), strict=False)
    except ValueError:
        raise ValueError(f"{text!r} is not an address or network (for example 10.0.0.5 or 172.29.77.0/24)")

    narrowest = 8 if network.version == 4 else 16

    if network.prefixlen < narrowest:
        raise ValueError(f"{text!r} is too wide to trust: it would include far more than one proxy")

    return str(network.network_address) if network.num_addresses == 1 else str(network)


def trusted_proxies(extra=()):
    """Addresses (and networks) whose X-Forwarded-* headers are believed. Anyone else could
    claim any client address and slip past per-address protections such as
    the login lockout."""

    return list(dict.fromkeys(["127.0.0.1", "::1", *(proxy_address(item) for item in extra)]))


def check(host, environ=os.environ, tls=False, behind_proxy=False,
          has_accounts=None, public=False):
    """Returns a message if this way of serving is unsafe, else None.

    public: a tunnel or proxy makes this server reachable from the internet even
    though it listens on this machine only, so sign-in is required regardless of host.
    """

    if is_local(host) and not public:
        return None

    if has_accounts is None:
        has_accounts = accounts_exist(environ.get("IDS_DB", "ids.db"))

    if not (environ.get("IDS_ADMIN_TOKEN") or has_accounts):
        return (
            f"Refusing to serve {'publicly' if public else 'on ' + host} with no way to sign in: "
            "anyone who can reach the site could start packet capture and change "
            "settings.\nCreate an account first:\n"
            "    python manage_users.py add alice --role admin\n"
            "or set IDS_ADMIN_TOKEN."
        )

    if not (tls or behind_proxy):
        return (
            f"Refusing to listen on {host} over plain HTTP: passwords and "
            "session tokens would cross the network in clear text.\n"
            "Use --self-signed, or --cert and --key, or --behind-proxy if a "
            "reverse proxy in front of this server already provides HTTPS."
        )

    return None


# -- certificates -------------------------------------------------------------

def host_entries(hosts):
    """Subject alternative names for the given host names and addresses."""

    from cryptography import x509

    names = []

    for host in hosts:

        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))

    return names


def default_hosts(extra=()):
    """Names a browser might use to reach this machine."""

    hosts = ["localhost", "127.0.0.1", "::1", socket.gethostname()]

    hosts += list(extra)

    seen = []

    for host in hosts:
        if host and host not in seen:
            seen.append(host)

    return seen


def make_self_signed(cert_path, key_path, hosts, days=365):
    """Write a self-signed certificate (ECDSA P-256) valid for the hosts."""

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = ec.generate_private_key(ec.SECP256R1())

    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Bayesian IDS")])

    now = datetime.datetime.now(datetime.timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName(host_entries(hosts)), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(key, hashes.SHA256())
    )

    Path(cert_path).parent.mkdir(parents=True, exist_ok=True)

    Path(cert_path).write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    Path(key_path).write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ))

    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass


def certificate_covers(cert_path, hosts, within_days=RENEW_WITHIN_DAYS):
    """True if the file is a certificate that is valid for a while yet and
    names every host."""

    from cryptography import x509

    try:
        certificate = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())
    except (OSError, ValueError):
        return False

    remaining = certificate.not_valid_after_utc - datetime.datetime.now(
        datetime.timezone.utc
    )

    if remaining < datetime.timedelta(days=within_days):
        return False

    present = certificate.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value

    have = {str(n.value) for n in present}

    return all(str(n.value) in have for n in host_entries(hosts))


def ensure_certificate(directory=CERT_DIR, extra_hosts=()):
    """(cert_path, key_path), generating a self-signed pair if needed."""

    cert = Path(directory) / "ids-selfsigned.pem"
    key = Path(directory) / "ids-selfsigned.key"

    hosts = default_hosts(extra_hosts)

    if not (key.exists() and certificate_covers(cert, hosts)):
        make_self_signed(cert, key, hosts)

    return str(cert), str(key)


def fingerprint(cert_path):
    """SHA-256 fingerprint, the way browsers display it."""

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    certificate = x509.load_pem_x509_certificate(Path(cert_path).read_bytes())

    digest = certificate.fingerprint(hashes.SHA256()).hex().upper()

    return ":".join(digest[i:i + 2] for i in range(0, len(digest), 2))


# -- command line ----------------------------------------------------------

def main(argv=None):

    envfile.load()

    parser = argparse.ArgumentParser(
        description="Start the Bayesian IDS server.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--cert", help="TLS certificate (PEM)")
    parser.add_argument("--key", help="TLS private key (PEM)")
    parser.add_argument("--self-signed", action="store_true",
                        help="generate (and reuse) a self-signed certificate in ./certs")
    parser.add_argument("--san", action="append", default=[],
                        help="extra host name or IP for the self-signed certificate")
    parser.add_argument("--behind-proxy", action="store_true",
                        help="a reverse proxy in front of this server provides HTTPS")
    parser.add_argument("--public", action="store_true",
                        help="a tunnel or proxy exposes this server to the internet: "
                             "implies --behind-proxy and refuses to start without accounts")
    parser.add_argument("--proxy-ip", action="append", default=[],
                        help="address or private network the proxy connects from, e.g. 10.0.0.5 or "
                             "172.29.77.0/24 (default 127.0.0.1 and ::1); X-Forwarded-For is believed "
                             "only from these")

    args = parser.parse_args(argv)

    if bool(args.cert) != bool(args.key):
        sys.exit("--cert and --key go together.")

    if args.self_signed and args.cert:
        sys.exit("Choose --self-signed or --cert/--key, not both.")

    cert, key = args.cert, args.key

    if args.self_signed:

        cert, key = ensure_certificate(extra_hosts=[args.host, *args.san]
                                       if not is_local(args.host) else args.san)

        print(f"Self-signed certificate: {cert}")
        print(f"SHA-256 fingerprint:     {fingerprint(cert)}")

    args.behind_proxy = args.behind_proxy or args.public

    try:
        proxies = trusted_proxies(args.proxy_ip)
    except ValueError as error:
        sys.exit(f"--proxy-ip: {error}")

    problem = check(args.host, tls=bool(cert), behind_proxy=args.behind_proxy, public=args.public)

    if problem:
        sys.exit(problem)

    config = uvicorn.Config(
        "api:app",
        host=args.host,
        port=args.port,
        ssl_certfile=cert,
        ssl_keyfile=key,
        proxy_headers=args.behind_proxy,
        forwarded_allow_ips=",".join(proxies) if args.behind_proxy else None,
        # the default "websockets" implementation is deprecated upstream
        ws="websockets-sansio",
        # do not announce the server software in every response
        server_header=False
    )

    server = uvicorn.Server(config)

    # lets the dashboard's Restart button shut this server down cleanly
    lifecycle.SERVER = server

    server.run()

if __name__ == "__main__":

    main()
