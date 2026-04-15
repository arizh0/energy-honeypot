#!/usr/bin/env python3
"""
HelioControl Solar Inverter Management Interface - HTTP honeypot.
Logs all requests and credential attempts as structured JSON to stdout
(picked up by Promtail -> Loki). Public HTTP/HTTPS traffic is proxied by nginx.
"""

import base64
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone

from flask import Flask, Response, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.secret_key = os.urandom(24)   # Random per container restart; sessions do not persist.
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB hard cap.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

_OPERATOR_IPS: frozenset[str] = frozenset(
    ip.strip() for ip in os.environ.get("OPERATOR_IPS", "").split(",") if ip.strip()
)

# Credentials that "work" - realistic defaults for an IoT/ICS device.
_VALID_USERS = {"admin", "root", "user", "helio", "administrator", "service"}
_VALID_PASSWORDS = {
    "admin", "admin123", "password", "password123", "1234", "12345",
    "123456", "12345678", "root", "toor", "helio", "helio123",
    "solar", "solar123", "inverter", "changeme", "default",
    "guest", "test", "qwerty", "letmein", "welcome", "",
}

_BROWSER_AUTH_PATHS = {"/dashboard"}
_API_AUTH_PREFIXES = ("/api/", "/firmware/")


def _auth_accepted(username: str, password: str) -> bool:
    """Return True if credentials match realistic device defaults."""
    return username in _VALID_USERS or password in _VALID_PASSWORDS


def _parse_basic_auth() -> tuple | None:
    auth = request.headers.get("Authorization", "")
    if not auth.lower().startswith("basic "):
        return None
    try:
        decoded = base64.b64decode(auth[6:]).decode(errors="replace")
        username, _, password = decoded.partition(":")
        return username, password
    except Exception:
        return None


def _raw_remote_addr() -> str:
    original = request.environ.get("werkzeug.proxy_fix.orig", {})
    return original.get("REMOTE_ADDR", request.remote_addr)


_SKIP_HEADERS = frozenset({"connection", "transfer-encoding", "te", "trailer", "upgrade"})


def log_request(event: str, **extra):
    print(json.dumps({
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "request_id":    getattr(g, "request_id", ""),
        "event":         event,
        "src_ip":        request.remote_addr,
        "remote_addr":   _raw_remote_addr(),
        "forwarded_for": request.headers.get("X-Forwarded-For", ""),
        "method":        request.method,
        "path":          request.path,
        "query":         request.query_string.decode(errors="replace"),
        "user_agent":    request.headers.get("User-Agent", ""),
        "referer":       request.headers.get("Referer", ""),
        "is_operator":   request.remote_addr in _OPERATOR_IPS,
        **extra,
    }), flush=True)


@app.before_request
def _init_request_context():
    g.start_time = time.monotonic()
    g.request_id = uuid.uuid4().hex[:8]
    # Read and cache body before any form/JSON parser consumes the stream.
    # Skip multipart uploads — they're captured separately in the firmware route.
    ct = request.content_type or ""
    if "multipart" not in ct:
        try:
            raw = request.get_data(cache=True, as_text=False)
            g.request_body = raw[:8192].decode("utf-8", errors="replace") if raw else None
        except Exception:
            g.request_body = None
    else:
        g.request_body = None


@app.after_request
def _log_response(response):
    duration_ms = round((time.monotonic() - g.start_time) * 1000, 2) if hasattr(g, "start_time") else None
    headers = {
        k: v for k, v in request.headers
        if k.lower() not in _SKIP_HEADERS
    }
    log_request(
        "http_request",
        status_code=response.status_code,
        response_bytes=response.content_length,
        duration_ms=duration_ms,
        content_type=request.content_type or "",
        content_length=request.content_length,
        headers=headers,
        body=getattr(g, "request_body", None),
        cookies=dict(request.cookies),
    )
    return response


@app.before_request
def require_auth_for_device_surfaces():
    path = request.path
    needs_browser_auth = path in _BROWSER_AUTH_PATHS
    needs_api_auth = path.startswith(_API_AUTH_PREFIXES)

    if not (needs_browser_auth or needs_api_auth) or session.get("auth"):
        return None

    creds = _parse_basic_auth()
    if creds:
        username, password = creds
        accepted = _auth_accepted(username, password)
        log_request("credential_attempt", username=username, password=password,
                    accepted=accepted, auth_type="basic", protected_path=path)
        if accepted:
            session["auth"] = True
            return None

    log_request("unauthenticated_access", protected_path=path)

    if needs_browser_auth:
        return redirect(url_for("login"))

    return jsonify({"status": "error", "message": "Authentication required"}), 401


@app.route("/robots.txt")
def robots():
    return Response(
        "User-agent: *\n"
        "Disallow: /admin/\n"
        "Disallow: /config/\n"
        "Disallow: /backup/\n"
        "Disallow: /api/\n"
        "Disallow: /firmware/\n"
        "Disallow: /debug/\n"
        "Disallow: /logs/\n"
        "Disallow: /shell/\n",
        mimetype="text/plain"
    )


@app.route("/admin")
@app.route("/admin/")
@app.route("/config")
@app.route("/settings")
@app.route("/manage")
@app.route("/panel")
@app.route("/debug")
@app.route("/shell")
@app.route("/backup")
def redirect_to_login():
    return redirect(url_for("login"))


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if request.is_json:
            body = request.get_json(silent=True) or {}
            username = str(body.get("username", ""))
            password = str(body.get("password", ""))
            auth_type = "json"
        else:
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            auth_type = "form"
        accepted = _auth_accepted(username, password)
        log_request("credential_attempt", username=username, password=password,
                    accepted=accepted, auth_type=auth_type)
        if accepted:
            session["auth"] = True
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/status")
def api_status():
    return jsonify({
        "device": "HC-5000",
        "serial": "HC5K-2024-00847",
        "firmware": "2.4.1",
        "status": "online",
        "solar_power_w": 3240,
        "grid_export_w": 1180,
        "battery_soc_pct": 78,
        "today_kwh": 12.4,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/config")
def api_config():
    return jsonify({
        "device": "HC-5000",
        "modbus_enabled": True,
        "modbus_address": 1,
        "modbus_port": 502,
        "mqtt_enabled": True,
        "mqtt_broker": "192.168.1.1",
        "mqtt_port": 1883,
    })


@app.route("/firmware/upload", methods=["POST"])
def firmware_upload():
    firmware = request.files.get("firmware")
    if firmware and firmware.filename:
        data = firmware.read()
        log_request(
            "firmware_upload",
            filename=firmware.filename,
            content_type=firmware.content_type or "",
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
        )
    else:
        log_request("firmware_upload_probe")

    return jsonify({
        "status": "success",
        "message": "Firmware queued for installation. Device will reboot in 60 seconds.",
        "version": "2.5.0",
    })


@app.errorhandler(413)
def too_large(_error):
    log_request("firmware_upload_oversized")
    return jsonify({"status": "error", "message": "File too large"}), 413


@app.errorhandler(404)
def not_found(_error):
    return "Not Found", 404


@app.errorhandler(Exception)
def handle_error(_error):
    return "Internal Server Error", 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
