# VulnScan Lite

> A lightweight, on-demand web security checker for websites you own.

VulnScan Lite is a Flask-based passive web vulnerability scanner. It accepts a public website URL, performs a small set of low-impact security checks, presents the findings in a browser dashboard, calculates an overall grade, and generates a downloadable PDF report.

The project is designed for learning, demonstrations, and quick security posture checks. It is **not** a penetration-testing framework and should not be treated as proof that a website is secure.

## Features

- Browser-based URL scanning interface
- Animated scanning state with progress messages
- Background scan execution using a daemon thread
- Polling-based status updates
- Security-header analysis
- SSL/TLS certificate and connection checks
- Basic CMS fingerprint detection
- Server and technology-information exposure checks
- Score from 0 to 100 and letter grade from A to F
- Passed and failed checks grouped by category
- Remediation advice for failed checks
- Downloadable PDF security report
- Request rate limiting
- Target validation to reject local and private network destinations
- Responsive dark-themed interface with reduced-motion support

## What the scanner checks

### 1. Security headers

The scanner sends an HTTP request and checks whether the response contains these headers:

| Header | Why it matters | Failure guidance |
| --- | --- | --- |
| `Content-Security-Policy` | Helps restrict script and resource sources and reduce some injection risks. | Add a policy appropriate for the application. |
| `X-Frame-Options` | Helps prevent clickjacking by controlling whether the site can be embedded in a frame. | Add `X-Frame-Options: DENY` or an appropriate equivalent. |
| `Strict-Transport-Security` | Tells browsers to use HTTPS for future requests. | Add an HSTS policy such as `max-age=31536000; includeSubDomains` after HTTPS is configured correctly. |

Each header contributes one check to the final result.

### 2. SSL / TLS

The scanner connects to port 443 using Python's default certificate-verifying SSL context and checks:

- Whether the certificate is valid and trusted
- How many days remain before the certificate expires
- Whether the negotiated protocol is TLS 1.2 or TLS 1.3
- Whether the negotiated cipher has at least 128-bit strength

If HTTPS cannot be reached or certificate verification fails, the report includes a failed check and a suggested corrective action.

### 3. CMS and server information

The scanner fetches the page HTML and looks for common fingerprints:

- WordPress
- Drupal
- Joomla

It also checks:

- Whether a detected CMS version appears below the minimum versions configured in `scanner/cms.py`
- Whether `X-Powered-By` exposes technology or version information
- Whether the `Server` header exposes a numeric server version

CMS detection is intentionally lightweight. It uses HTML generator metadata, known page markers, and response headers; it does not crawl a site or attempt exploitation.

## Scoring and grades

Every individual check contributes:

- `+10` points when it passes
- `-10` points when it fails

The dashboard score is calculated from the number of passed checks:

```text
score = passed checks / total checks × 100
```

The letter grade thresholds are:

| Score | Grade |
| ---: | :--- |
| 90–100 | A |
| 80–89 | B |
| 65–79 | C |
| 50–64 | D |
| 0–49 | F |

The score is an educational summary of the checks implemented by this project. It is not a universal security rating.

## How a scan works

```text
1. User enters a URL
        │
        ▼
2. Browser sends POST /api/scan
        │
        ├─ Validate and resolve the target
        ├─ Reject local/private/reserved destinations
        └─ Create a queued job
                │
                ▼
3. Background thread runs the scanner modules
        ├─ scanner/headers.py
        ├─ scanner/ssl_check.py
        └─ scanner/cms.py
                │
                ▼
4. Browser polls GET /api/scan/<job_id>/status
        │
        ▼
5. Results appear in the dashboard
        │
        ▼
6. User downloads GET /api/scan/<job_id>/pdf
```

The application currently uses an in-process Python daemon thread for background work. It does **not** use Celery, Redis, a database, or a persistent job queue. Jobs and scan results are held in memory and disappear when the process restarts.

## PDF reports

When a scan completes, the dashboard provides a **Download PDF report** link. The report includes:

- Report title
- Scanned target
- Generation date and time
- Overall grade and score
- Number of passed checks
- Category-by-category check tables
- Passed or failed status for each check
- “How to fix” guidance for failed checks
- Passive-analysis safety disclaimer

PDF generation is implemented in `report.py` with ReportLab.

## Safety controls and scope

**Only scan websites you own or have explicit permission to test.**

VulnScan Lite is intended for passive, low-impact checks. It does not:

- Exploit vulnerabilities
- Brute-force accounts
- Crawl all site paths
- Perform destructive requests
- Test authentication controls
- Prove that a website is secure

Before a scan starts, the application resolves the target hostname and rejects addresses that are private, loopback, link-local, reserved, or multicast. This is an application-level safeguard, not a replacement for firewall rules, egress filtering, authentication, or other deployment controls.

The scan modules also apply request timeouts and follow normal HTTP redirects through the `requests` library.

## Rate limiting

The `POST /api/scan` endpoint is limited to five requests per minute per client address using Flask-Limiter with in-memory storage.

When the limit is exceeded, the API returns HTTP `429` with:

```json
{
  "error": "Too many scans. Please wait a minute and try again."
}
```

For a multi-worker or production deployment, configure a shared rate-limit backend instead of in-memory storage.

## Local setup

### Requirements

- Python 3.10 or newer recommended
- Network access to authorized sites you intend to check
- A modern browser

### Installation

```bash
git clone https://github.com/sarkarayan1112-lab/VulnScan-Lite.git
cd VulnScan-Lite

python -m venv .venv
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate

python -m pip install -r requirements.txt
```

### Start the development server

```bash
python app.py
```

Open [http://localhost:5001](http://localhost:5001).

The Flask development server runs on port `5001` and serves the interface from `templates/index.html`.

### Run with Gunicorn

The repository includes Gunicorn for a production-style WSGI process:

```bash
gunicorn --bind 0.0.0.0:5001 app:app
```

Before exposing the service publicly, configure HTTPS, a reverse proxy, access controls, secure environment settings, logging, firewall rules, and a process manager appropriate for your deployment.

## API reference

### Start a scan

```http
POST /api/scan
Content-Type: application/json
```

Request:

```json
{
  "url": "https://example.com"
}
```

Successful response: HTTP `202`

```json
{
  "job_id": "job-uuid",
  "status": "queued"
}
```

Possible errors include:

- HTTP `400` when the URL is missing, invalid, blocked, or cannot be resolved
- HTTP `429` when the rate limit is exceeded

### Read scan status

```http
GET /api/scan/<job_id>/status
```

Queued response:

```json
{
  "job_id": "job-uuid",
  "status": "queued",
  "result": null
}
```

Completed responses include the target, score, grade, check counts, and detailed results grouped under `headers`, `ssl`, and `cms`.

### Download a report

```http
GET /api/scan/<job_id>/pdf
```

The endpoint returns a PDF attachment when the job has completed. It returns HTTP `404` if the job does not exist or the report is not ready.

## Project structure

```text
VulnScan-Lite/
├── app.py
│   ├── Flask application setup
│   ├── target hostname/IP validation
│   ├── rate limiting
│   ├── scan job lifecycle
│   └── JSON and PDF routes
├── report.py
│   └── ReportLab PDF generation
├── scanner/
│   ├── __init__.py
│   ├── headers.py
│   │   └── HTTP security-header checks
│   ├── ssl_check.py
│   │   └── certificate, expiry, TLS, and cipher checks
│   └── cms.py
│       └── CMS fingerprints and information-leak checks
├── templates/
│   └── index.html
│       └── browser UI, animations, polling, results, and PDF link
├── requirements.txt
│   └── Python dependencies
└── README.md
    └── project documentation
```

## Main dependencies

| Package | Purpose |
| --- | --- |
| Flask | Web server and API routes |
| Requests | HTTP requests to scan targets |
| BeautifulSoup | HTML parsing for CMS detection |
| Flask-Limiter | Scan-request rate limiting |
| ReportLab | PDF report generation |
| Gunicorn | WSGI server for deployment |

## Limitations

- Scan state is stored in process memory.
- Results are not persistent across restarts.
- Results are not shared between multiple application workers.
- There is no login system or per-user scan history.
- The scanner performs a limited set of passive checks rather than a full security audit.
- CMS version detection depends on information exposed by the target.
- Some websites may block automated requests, require authentication, or return different headers to different clients.
- Certificate expiry and TLS results describe the connection made by the scanner at scan time.

## Suggested improvements

Possible next steps for a larger deployment include:

- Replace the in-process thread with Celery/RQ and Redis.
- Store jobs and results in a database.
- Add authentication and per-user scan history.
- Add structured logging and monitoring.
- Use a shared rate-limit store for multiple workers.
- Add automated tests for validators, scoring, scanner modules, and API routes.
- Add a configurable check registry instead of hard-coding module discovery.

## Development notes

Scanner modules return a consistent structure containing a list of checks. Each check includes a name, a Boolean `passed` value, and optional remediation text:

```python
{
    "results": [
        {
            "check": "Content-Security-Policy",
            "passed": True,
            "fix": None,
        }
    ]
}
```

This makes the same scan data usable by the web dashboard and the PDF generator.

## License

No license file is currently included in the repository. Review and add an appropriate license before redistributing the project.