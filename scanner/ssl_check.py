import socket
import ssl
from datetime import datetime, timezone


def clean_hostname(target):
    target = target.replace("https://", "").replace("http://", "")
    target = target.split("/")[0]
    target = target.split(":")[0]
    return target


def check_ssl(target):
    hostname = clean_hostname(target)
    context = ssl.create_default_context()

    try:
        with socket.create_connection((hostname, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cipher_name, _, cipher_bits = ssock.cipher()
                tls_version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        return {
            "hostname": hostname,
            "score": -10,
            "results": [{
                "check": "SSL Certificate Valid",
                "passed": False,
                "fix": "Install a valid certificate from a trusted CA (e.g. Let's Encrypt). Error: " + str(e.verify_message),
            }],
        }
    except Exception as e:
        return {
            "hostname": hostname,
            "score": -10,
            "results": [{
                "check": "HTTPS Available",
                "passed": False,
                "fix": "Could not connect on port 443. Enable HTTPS on your server. Error: " + str(e),
            }],
        }

    expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    expiry = expiry.replace(tzinfo=timezone.utc)
    days_left = (expiry - datetime.now(timezone.utc)).days

    checks = [
        ("SSL Certificate Valid", True, None),
        (
            "Certificate Expiry (" + str(days_left) + " days left)",
            days_left > 30,
            "Renew your certificate soon. Use auto-renewal (e.g. certbot).",
        ),
        (
            "TLS Version (" + tls_version + ")",
            tls_version in ("TLSv1.2", "TLSv1.3"),
            "Disable old TLS versions and enable TLS 1.2 or TLS 1.3 only.",
        ),
        (
            "Cipher Strength (" + cipher_name + ", " + str(cipher_bits) + " bit)",
            cipher_bits >= 128,
            "Configure your server to use strong ciphers (128-bit or higher).",
        ),
    ]

    results = []
    score = 0
    for name, passed, fix in checks:
        score += 10 if passed else -10
        results.append({"check": name, "passed": passed, "fix": None if passed else fix})

    return {"hostname": hostname, "score": score, "results": results}