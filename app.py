import ipaddress
import socket
import threading
import uuid
from urllib.parse import urlparse

from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, jsonify, render_template, request, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from report import build_pdf
from scanner.cms import check_cms
from scanner.headers import check_headers
from scanner.ssl_check import check_ssl

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)
limiter = Limiter(get_remote_address, app=app, storage_uri="memory://")
jobs = {}


@app.errorhandler(429)
def too_many_requests(e):
    return jsonify({"error": "Too many scans. Please wait a minute and try again."}), 429


def get_hostname(target):
    if not target.startswith("http"):
        target = "https://" + target
    return urlparse(target).hostname


def is_safe_target(target):
    """Block localhost / private IPs so nobody can scan our own server (SSRF protection)."""
    hostname = get_hostname(target)
    if not hostname:
        return False
    try:
        infos = socket.getaddrinfo(hostname, 443)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast):
            return False
    return True


def get_grade(percent):
    if percent >= 90:
        return "A"
    if percent >= 80:
        return "B"
    if percent >= 65:
        return "C"
    if percent >= 50:
        return "D"
    return "F"


def run_scan(job_id, target):
    jobs[job_id]["status"] = "running"
    modules = {"headers": check_headers, "ssl": check_ssl, "cms": check_cms}
    report = {}
    passed_count = 0
    total_count = 0

    for name, func in modules.items():
        try:
            data = func(target)
        except Exception as e:
            data = {
                "score": -10,
                "results": [{
                    "check": name + " scan",
                    "passed": False,
                    "fix": "Scan could not complete: " + str(e),
                }],
            }
        report[name] = data
        for item in data["results"]:
            total_count += 1
            if item["passed"]:
                passed_count += 1

    percent = round(passed_count / total_count * 100) if total_count else 0
    jobs[job_id]["result"] = {
        "target": target,
        "score": percent,
        "grade": get_grade(percent),
        "passed_checks": passed_count,
        "total_checks": total_count,
        "details": report,
    }
    jobs[job_id]["status"] = "completed"


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
@limiter.limit("5 per minute")
def start_scan():
    data = request.get_json(silent=True) or {}
    target = data.get("url", "").strip()

    if not target:
        return jsonify({"error": "Please provide a url."}), 400
    if not is_safe_target(target):
        return jsonify({"error": "This target is not allowed or could not be resolved."}), 400

    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "queued", "result": None}
    threading.Thread(target=run_scan, args=(job_id, target), daemon=True).start()
    return jsonify({"job_id": job_id, "status": "queued"}), 202


@app.route("/api/scan/<job_id>/status")
def scan_status(job_id):
    job = jobs.get(job_id)
    if job is None:
        return jsonify({"error": "Job not found."}), 404
    return jsonify({"job_id": job_id, "status": job["status"], "result": job["result"]})


@app.route("/api/scan/<job_id>/pdf")
def scan_pdf(job_id):
    job = jobs.get(job_id)
    if job is None or job["status"] != "completed":
        return jsonify({"error": "Report not ready."}), 404
    pdf = build_pdf(job["result"])
    return send_file(
        pdf,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="vulnscan-report.pdf",
    )


if __name__ == "__main__":
    app.run(debug=True, port=5001)