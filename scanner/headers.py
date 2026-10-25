import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": "Add a Content-Security-Policy header to block XSS and injection attacks.",
    "X-Frame-Options": "Add 'X-Frame-Options: DENY' to prevent clickjacking.",
    "Strict-Transport-Security": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to force HTTPS.",
}


def check_headers(url):
    if not url.startswith("http"):
        url = "https://" + url

    resp = requests.get(url, timeout=10, allow_redirects=True)

    results = []
    score = 0
    for header, fix in SECURITY_HEADERS.items():
        present = header in resp.headers
        score += 10 if present else -10
        results.append({
            "check": header,
            "passed": present,
            "fix": None if present else fix,
        })

    return {"url": url, "score": score, "results": results}