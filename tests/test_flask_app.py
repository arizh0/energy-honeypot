import base64
import importlib.util
import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_PATH = ROOT / "flask-fallback" / "app.py"

try:
    import flask  # noqa: F401
    FLASK_AVAILABLE = True
except ModuleNotFoundError:
    FLASK_AVAILABLE = False


def load_app_module():
    spec = importlib.util.spec_from_file_location("flask_honeypot_app", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Flask resolves root_path (for templates) from sys.modules at import time.
    # importlib-loaded modules aren't registered there, so Flask falls back to
    # cwd and can't find flask-fallback/templates/. Fix it explicitly.
    module.app.root_path = str(APP_PATH.parent)
    module.app.config.update(TESTING=True)
    return module


@unittest.skipUnless(FLASK_AVAILABLE, "Flask is not installed in this Python environment")
class FlaskHoneypotTests(unittest.TestCase):
    def setUp(self):
        self.module = load_app_module()
        self.client = self.module.app.test_client()

    def test_dashboard_requires_login(self):
        response = self.client.get("/dashboard")

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.headers["Location"])

    def test_api_requires_login(self):
        response = self.client.get("/api/status")

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.get_json()["message"], "Authentication required")

    def test_valid_login_allows_dashboard(self):
        login = self.client.post("/login", data={"username": "admin", "password": "admin"})
        dashboard = self.client.get("/dashboard")

        self.assertEqual(login.status_code, 302)
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn(b"HelioControl", dashboard.data)

    def test_basic_auth_credentials_logged_on_api_endpoint(self):
        token = base64.b64encode(b"admin:admin").decode()
        output = io.StringIO()
        with redirect_stdout(output):
            self.client.get("/api/status", headers={"Authorization": f"Basic {token}"})
        logs = [json.loads(line) for line in output.getvalue().splitlines()]
        cred_logs = [entry for entry in logs if entry.get("event") == "credential_attempt"]
        self.assertEqual(len(cred_logs), 1)
        self.assertEqual(cred_logs[0]["username"], "admin")
        self.assertEqual(cred_logs[0]["password"], "admin")
        self.assertEqual(cred_logs[0]["auth_type"], "basic")

    def test_json_body_credentials_logged_on_login(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.client.post(
                "/login",
                data=json.dumps({"username": "root", "password": "toor"}),
                content_type="application/json",
            )
        logs = [json.loads(line) for line in output.getvalue().splitlines()]
        cred_logs = [entry for entry in logs if entry.get("event") == "credential_attempt"]
        self.assertEqual(len(cred_logs), 1)
        self.assertEqual(cred_logs[0]["username"], "root")
        self.assertEqual(cred_logs[0]["auth_type"], "json")

    def test_logs_include_trusted_and_raw_source_fields(self):
        output = io.StringIO()

        with redirect_stdout(output):
            self.client.get("/login", headers={"X-Forwarded-For": "198.51.100.7"})

        # http_request is logged in after_request; it's the only log line for GET /login
        logs = [json.loads(line) for line in output.getvalue().splitlines()]
        http_logs = [e for e in logs if e.get("event") == "http_request"]
        self.assertEqual(len(http_logs), 1)
        entry = http_logs[0]
        self.assertEqual(entry["src_ip"], "198.51.100.7")
        self.assertEqual(entry["remote_addr"], "127.0.0.1")
        self.assertEqual(entry["forwarded_for"], "198.51.100.7")

    def test_http_request_log_includes_timing_and_status(self):
        output = io.StringIO()

        with redirect_stdout(output):
            self.client.get("/login")

        logs = [json.loads(line) for line in output.getvalue().splitlines()]
        http_logs = [e for e in logs if e.get("event") == "http_request"]
        self.assertEqual(len(http_logs), 1)
        entry = http_logs[0]
        self.assertIn("duration_ms", entry)
        self.assertIn("status_code", entry)
        self.assertIn("request_id", entry)
        self.assertIn("headers", entry)
        self.assertEqual(entry["status_code"], 200)

    def test_http_request_log_includes_request_id_matching_credential_attempt(self):
        token = base64.b64encode(b"admin:admin").decode()
        output = io.StringIO()

        with redirect_stdout(output):
            self.client.get("/api/status", headers={"Authorization": f"Basic {token}"})

        logs = [json.loads(line) for line in output.getvalue().splitlines()]
        cred_log = next(e for e in logs if e.get("event") == "credential_attempt")
        http_log = next(e for e in logs if e.get("event") == "http_request")
        self.assertEqual(cred_log["request_id"], http_log["request_id"])


if __name__ == "__main__":
    unittest.main()
