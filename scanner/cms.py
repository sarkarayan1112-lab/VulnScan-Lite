import re
import requests
from bs4 import BeautifulSoup

# Minimum versions we consider "up to date enough". Update these from time to time.
MIN_VERSIONS = {
    "WordPress": (6, 6),
    "Drupal": (10, 0),
    "Joomla": (5, 0),
}
MIN_PHP = (8, 2)


def parse_version(text):
    match = re.search(r"(\d+)\.(\d+)", text or "")
    if match:
        return (int(match.group(1)), int(match.group(2)))
    return None


def version_str(version):
    return ".".join(str(part) for part in version)


def detect_cms(resp, soup):
    meta = soup.find("meta", attrs={"name": "generator"})
    generator = meta.get("content", "") if meta else ""
    html = resp.text.lower()
    x_generator = resp.headers.get("X-Generator", "")

    cms = None
    if "wordpress" in generator.lower() or "wp-content" in html:
        cms = "WordPress"
    elif "drupal" in generator.lower() or "drupal" in x_generator.lower():
        cms = "Drupal"
    elif "joomla" in generator.lower():
        cms = "Joomla"

    version = None
    if cms and cms.lower() in generator.lower():
        version = parse_version(generator)
    return cms, version


def check_cms(url):
    if not url.startswith("http"):
        url = "https://" + url

    resp = requests.get(url, timeout=10, allow_redirects=True)
    soup = BeautifulSoup(resp.text, "html.parser")
    cms, version = detect_cms(resp, soup)

    checks = []

    # Check 1: CMS version
    if cms is None:
        checks.append(("CMS Detection (no known CMS found)", True, None))
    elif version is None:
        checks.append(("CMS Detection (" + cms + ", version hidden)", True, None))
    else:
        outdated = version < MIN_VERSIONS[cms]
        checks.append((
            "CMS Version (" + cms + " " + version_str(version) + ")",
            not outdated,
            "Update " + cms + " to the latest version (at least " + version_str(MIN_VERSIONS[cms]) + ").",
        ))

    # Check 2: X-Powered-By leaks technology / version
    powered_by = resp.headers.get("X-Powered-By")
    if powered_by:
        php_version = parse_version(powered_by) if "php" in powered_by.lower() else None
        if php_version and php_version < MIN_PHP:
            checks.append((
                "X-Powered-By exposes outdated PHP (" + powered_by + ")",
                False,
                "Upgrade PHP to " + version_str(MIN_PHP) + " or newer and remove the X-Powered-By header.",
            ))
        else:
            checks.append((
                "X-Powered-By header exposed (" + powered_by + ")",
                False,
                "Remove the X-Powered-By header. In PHP set expose_php = Off. In Nginx use 'proxy_hide_header X-Powered-By;'.",
            ))
    else:
        checks.append(("X-Powered-By header hidden", True, None))

    # Check 3: Server header leaks version
    server = resp.headers.get("Server", "")
    if re.search(r"\d+\.\d+", server):
        checks.append((
            "Server header exposes version (" + server + ")",
            False,
            "Hide the server version. Nginx: 'server_tokens off;'. Apache: 'ServerTokens Prod'.",
        ))
    else:
        checks.append(("Server header does not expose version", True, None))

    results = []
    score = 0
    for name, passed, fix in checks:
        score += 10 if passed else -10
        results.append({"check": name, "passed": passed, "fix": None if passed else fix})

    return {"url": url, "cms": cms, "score": score, "results": results}