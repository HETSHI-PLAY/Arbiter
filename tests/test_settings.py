"""Settings API contracts with synthetic in-memory storage; never a live database."""
from __future__ import annotations

import json
import os
import unittest
from typing import Any
from unittest.mock import patch

from cryptography.fernet import Fernet

from tests import test_ui_api as ui_api


class SettingsAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ui_api.UIAPIContractTests.setUpClass.__func__(cls)

    def setUp(self):
        ui_api.UIAPIContractTests.setUp(self)  # type: ignore[arg-type]
        self.db.connection.create_function("now", 0, lambda: "2026-01-01T12:00:00Z")
        self.secret = patch.dict(os.environ, {"ARBITER_SECRET_KEY": Fernet.generate_key().decode()})
        self.secret.start()
        self.addCleanup(self.secret.stop)

    tearDown = ui_api.UIAPIContractTests.tearDown
    db: Any
    client: Any
    api: Any

    def test_defaults_are_safe_and_never_include_a_password_field(self):
        response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200, response.text)
        settings = response.json()["settings"]
        self.assertEqual(settings["wazuh"]["index_pattern"], "wazuh-alerts-*")
        self.assertFalse(settings["wazuh"]["enabled"])
        self.assertFalse(settings["realtime"]["enabled"])
        self.assertEqual(settings["ui"]["sidebar_default"], "expanded")
        self.assertNotIn("password", settings["wazuh"])
        self.assertFalse(settings["wazuh"]["password_set"])

    def test_intel_web_url_and_abuseipdb_key_are_configurable_and_redacted(self):
        saved = self.client.put("/api/settings", json={
            "intel": {"web_url": "http://192.168.30.10:3001/ip/", "abuseipdb_api_key": "SyntheticAbuseKey999"}
        })
        self.assertEqual(saved.status_code, 200, saved.text)
        intel = saved.json()["settings"]["intel"]
        self.assertEqual(intel["web_url"], "http://192.168.30.10:3001")
        self.assertTrue(intel["abuseipdb_key_set"])
        self.assertNotIn("SyntheticAbuseKey999", saved.text)
        self.assertNotIn("abuseipdb_key_enc", intel)

        bad = self.client.put("/api/settings", json={"intel": {"web_url": "javascript:alert(1)"}})
        self.assertEqual(bad.status_code, 400, bad.text)

        captured = {}

        def fake_enrich(ip, api_key=None, remote_url=None):
            captured["api_key"] = api_key
            return {"ip": ip, "status": "enriched", "abuse_score": 42, "reputation_source": "abuseipdb"}

        with patch.object(self.api, "enrich_ip", side_effect=fake_enrich), \
             patch.object(self.api, "upsert_ip_cache"), \
             patch.object(self.api, "sync_remote_cache") as synced:
            response = self.client.post("/api/intel/enrich", json={"ips": ["203.0.113.7"]})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(captured["api_key"], "SyntheticAbuseKey999")
        synced.assert_called_once()
        self.assertNotIn("SyntheticAbuseKey999", response.text)

    def test_enrich_ip_falls_back_to_remote_ip_intel_database(self):
        from app import intel as intel_mod
        remote_row = {"ip": "9.9.9.9", "status": "enriched", "abuse_score": 77, "reputation_source": "ip_intel_db"}
        with patch.object(intel_mod, "ABUSEIPDB_API_KEY", ""), \
             patch.object(intel_mod, "lookup_remote_ip_cache", return_value=remote_row) as looked:
            result = intel_mod.enrich_ip("9.9.9.9")
        looked.assert_called_once()
        self.assertEqual(result["reputation_source"], "ip_intel_db")
        self.assertEqual(result["abuse_score"], 77)

        with patch.object(intel_mod, "ABUSEIPDB_API_KEY", ""), \
             patch.object(intel_mod, "lookup_remote_ip_cache", return_value=None):
            missing = intel_mod.enrich_ip("9.9.9.10")
        self.assertEqual(missing["status"], "error")

    def test_saved_password_is_never_returned_and_survives_partial_updates(self):
        saved = self.client.put("/api/settings", json={
            "wazuh": {
                "enabled": True,
                "indexer_url": "https://wazuh.lab:9200/",
                "username": "analyst",
                "password": "SyntheticSecret123",
                "index_pattern": "wazuh-alerts-*",
                "verify_tls": False,
            }
        })
        self.assertEqual(saved.status_code, 200, saved.text)
        body = saved.json()["settings"]
        self.assertNotIn("password", body["wazuh"])
        self.assertTrue(body["wazuh"]["password_set"])
        self.assertEqual(body["wazuh"]["indexer_url"], "https://wazuh.lab:9200")
        self.assertNotIn("SyntheticSecret123", saved.text)

        partial = self.client.put("/api/settings", json={"realtime": {"enabled": True, "interval_seconds": 60}})
        self.assertEqual(partial.status_code, 200, partial.text)
        self.assertTrue(partial.json()["settings"]["wazuh"]["password_set"])
        self.assertNotIn("SyntheticSecret123", partial.text)

        reread = self.client.get("/api/settings").json()["settings"]
        self.assertEqual(reread["wazuh"]["username"], "analyst")
        self.assertTrue(reread["wazuh"]["password_set"])
        self.assertEqual(reread["realtime"]["interval_seconds"], 60)

    def test_invalid_fields_are_rejected_without_persisting(self):
        for payload, field in [
            ({"wazuh": {"indexer_url": "ftp://wazuh"}}, "http://"),
            ({"wazuh": {"index_pattern": "bad pattern!"}}, "Pola indeks"),
            ({"realtime": {"interval_seconds": 5}}, "Interval"),
            ({"ui": {"sidebar_default": "hidden"}}, "sidebar_default"),
        ]:
            response = self.client.put("/api/settings", json=payload)
            self.assertEqual(response.status_code, 400, response.text)
            self.assertIn(field, response.json()["detail"])
        stored = self.client.get("/api/settings").json()["settings"]
        self.assertEqual(stored["wazuh"]["indexer_url"], "")

    def test_connection_probe_uses_stored_password_and_maps_failures(self):
        self.client.put("/api/settings", json={"wazuh": {"indexer_url": "https://wazuh.lab:9200", "username": "analyst", "password": "stored"}})
        captured = {}

        def fake_probe(**kwargs):
            captured.update(kwargs)
            return {"ok": True, "status": 200, "count": 12, "index_pattern": kwargs["index_pattern"]}

        with patch.object(self.api, "test_wazuh_connection", fake_probe):
            response = self.client.post("/api/settings/wazuh/test", json={})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["count"], 12)
        self.assertEqual(captured["password"], "stored")

        def failing_probe(**kwargs):
            raise ValueError("Tidak dapat terhubung ke Wazuh Indexer. Periksa URL dan jaringan.")

        with patch.object(self.api, "test_wazuh_connection", failing_probe):
            failed = self.client.post("/api/settings/wazuh/test", json={"indexer_url": "https://wazuh.lab:9200"})
        self.assertEqual(failed.status_code, 502)
        self.assertIn("Tidak dapat terhubung", failed.json()["detail"])
        self.assertNotIn("stored", failed.text)

    def test_connection_probe_rejects_non_boolean_tls_flag(self):
        response = self.client.post("/api/settings/wazuh/test", json={"indexer_url": "https://wazuh.lab:9200", "verify_tls": "no"})
        self.assertEqual(response.status_code, 400)

    def test_connection_probe_counts_only_medium_severity_and_above(self):
        import json as json_module
        from app.settings import MIN_RULE_LEVEL, wazuh_alert_query, test_wazuh_connection

        self.assertEqual(MIN_RULE_LEVEL, 7)
        self.assertEqual(
            wazuh_alert_query(),
            {"query": {"range": {"rule.level": {"gte": 7}}}},
        )

        captured = {}

        class FakeResponse:
            status = 200

            def read(self, limit):
                return b'{"count": 42}'

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class FakeOpener:
            def open(self, request, timeout):
                captured["request"] = request
                captured["timeout"] = timeout
                return FakeResponse()

        with patch("app.settings.urllib.request.build_opener", return_value=FakeOpener()):
            result = test_wazuh_connection(
                indexer_url="https://wazuh.lab:9200",
                username="analyst",
                password="secret",
                index_pattern="wazuh-alerts-*",
                verify_tls=True,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(result["count"], 42)
        self.assertEqual(result["min_rule_level"], 7)
        request = captured["request"]
        self.assertEqual(request.get_method(), "POST")
        sent = json_module.loads(request.data.decode("utf-8"))
        self.assertEqual(sent["query"]["range"]["rule.level"]["gte"], 7)
        self.assertNotIn("secret", request.full_url)

    def test_password_is_encrypted_at_rest_and_never_serialized_to_clients(self):
        from app.settings import load_settings, wazuh_password

        self.client.put("/api/settings", json={
            "wazuh": {"indexer_url": "https://wazuh.lab:9200", "username": "analyst", "password": "SyntheticSecret123"}
        })
        row = self.db.connection.execute("SELECT value FROM wazuh.app_settings WHERE key = 'app'").fetchone()
        stored = row["value"] if isinstance(row, dict) else json.loads(row[0])
        raw = json.dumps(stored)
        self.assertNotIn("SyntheticSecret123", raw)
        self.assertTrue(stored["wazuh"]["password_enc"].startswith("fernet:v1:"))

        with self.db.session() as conn:
            loaded = load_settings(conn)
        self.assertEqual(wazuh_password(loaded), "SyntheticSecret123")

        response = self.client.get("/api/settings")
        self.assertNotIn("SyntheticSecret123", response.text)
        self.assertNotIn("password_enc", response.text)
        self.assertTrue(response.json()["settings"]["wazuh"]["password_set"])

    def test_wrong_local_key_never_exposes_or_crashes_saved_password(self):
        from app.settings import load_settings, wazuh_password

        self.client.put("/api/settings", json={"wazuh": {"password": "SyntheticSecret123"}})
        with patch.dict(os.environ, {"ARBITER_SECRET_KEY": Fernet.generate_key().decode()}):
            with self.db.session() as conn:
                loaded = load_settings(conn)
            self.assertEqual(wazuh_password(loaded), "")
            response = self.client.get("/api/settings")
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.json()["settings"]["wazuh"]["password_set"])
        self.assertNotIn("SyntheticSecret123", response.text)

    def test_legacy_plaintext_password_is_migrated_to_ciphertext(self):
        from app.settings import load_settings, migrate_settings, wazuh_password

        legacy = {"wazuh": {"indexer_url": "https://wazuh.lab:9200", "password": "LegacyPlain123"}}
        self.db.connection.execute(
            "INSERT INTO wazuh.app_settings (key, value, updated_at) VALUES ('app', ?, '2026-01-01')",
            (json.dumps(legacy),),
        )
        with self.db.session() as conn:
            self.assertTrue(migrate_settings(conn))
            row = conn.execute("SELECT value FROM wazuh.app_settings WHERE key = 'app'").fetchone()
            stored = row["value"] if isinstance(row, dict) else json.loads(row[0])
            self.assertNotIn("LegacyPlain123", json.dumps(stored))
            self.assertTrue(stored["wazuh"]["password_enc"].startswith("fernet:v1:"))
            self.assertEqual(wazuh_password(load_settings(conn)), "LegacyPlain123")
            self.assertFalse(migrate_settings(conn), "second run has nothing to migrate")

    def test_generated_key_file_lives_outside_the_repo_with_0600_mode(self):
        import stat
        import tempfile
        from pathlib import Path
        from app.secure_store import decrypt_text, encrypt_text

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "nested" / "secret.key"
            with patch.dict(os.environ, {"ARBITER_SECRET_KEY": "", "ARBITER_SECRET_KEY_FILE": str(path)}):
                token = encrypt_text("SyntheticSecret123")
                self.assertEqual(decrypt_text(token), "SyntheticSecret123")
            self.assertTrue(path.exists())
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertNotIn("SyntheticSecret123", token)

    # ── Wazuh timestamp normalization (fixes HTTP 400 on the since range) ──

    def test_wazuh_timestamp_normalization_collapses_colon_offset(self):
        from app.settings import _normalize_wazuh_timestamp, _valid_timestamp
        # Python isoformat emits +00:00; Wazuh Indexer's date parser wants +0000.
        self.assertEqual(
            _normalize_wazuh_timestamp("2026-11-06T01:12:41.963193+00:00"),
            "2026-11-06T01:12:41.963193+0000",
        )
        self.assertEqual(
            _normalize_wazuh_timestamp("2026-11-06T01:12:41.963193-07:30"),
            "2026-11-06T01:12:41.963193-0730",
        )
        # A 'Z' suffix and a colonless offset are left untouched.
        self.assertEqual(_normalize_wazuh_timestamp("2026-11-06T01:12:41Z"), "2026-11-06T01:12:41Z")
        self.assertEqual(_normalize_wazuh_timestamp("2026-11-06T01:12:41.963193+0000"), "2026-11-06T01:12:41.963193+0000")

    def test_wazuh_valid_timestamp_guards_garbage(self):
        from app.settings import _valid_timestamp
        self.assertTrue(_valid_timestamp("2026-11-06T01:12:41.963193+0000"))
        self.assertTrue(_valid_timestamp("2026-11-06T01:12:41Z"))
        self.assertFalse(_valid_timestamp(""))
        self.assertFalse(_valid_timestamp("not-a-date"))

    def test_wazuh_search_sends_normalized_since_timestamp(self):
        import json as json_module
        from app.settings import wazuh_search

        captured = {}

        class FakeResponse:
            status = 200
            def read(self, limit):
                return b'{"hits":{"hits":[]}}'
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False

        class FakeOpener200:
            def open(self, request, timeout):
                captured["request"] = request
                return FakeResponse()

        with patch("app.settings._wazuh_opener", return_value=FakeOpener200()):
            wazuh_search(
                indexer_url="https://wazuh.lab:9200",
                username="analyst",
                password="secret",
                index_pattern="wazuh-alerts-*",
                verify_tls=True,
                size=10,
                since="2026-11-06T01:12:41.963193+00:00",
            )
        sent = json_module.loads(captured["request"].data.decode("utf-8"))
        self.assertEqual(
            sent["query"]["bool"]["must"],
            [
                {"range": {"rule.level": {"gte": 7}}},
                {"range": {"timestamp": {"gte": "2026-11-06T01:12:41.963193+0000"}}},
            ],
        )
        self.assertNotIn("+00:00", json_module.dumps(sent))

        # Test DD/MM/YYYY HH.MM.SS and until parameter
        with patch("app.settings._wazuh_opener", return_value=FakeOpener200()):
            wazuh_search(
                indexer_url="https://wazuh.lab:9200",
                username="analyst",
                password="secret",
                index_pattern="wazuh-alerts-*",
                verify_tls=True,
                size=250,
                since="08/11/2026 17.00.00",
                until="09/11/2026 08:30:00",
                min_rule_level=7,
                max_rule_level=11,
            )
        sent_range = json_module.loads(captured["request"].data.decode("utf-8"))
        self.assertEqual(
            sent_range["query"]["bool"]["must"],
            [
                {"range": {"rule.level": {"gte": 7, "lte": 11}}},
                {
                    "range": {
                        "timestamp": {
                            "gte": "2026-11-08T17:00:00+0700",
                            "lte": "2026-11-09T08:30:00+0700",
                        }
                    }
                },
            ],
        )

    def test_wazuh_http_error_reason_surfaces_upstream_body(self):
        from app.settings import _http_error_reason
        import urllib.error as urlerror

        class FakeHTTPError(urlerror.HTTPError):
            def __init__(self):
                super().__init__("https://wazuh.lab:9200", 400, "Bad Request", None, None)
                self._body = b'{"error":{"reason":"failed to parse date field"}}'

            def read(self, limit=None):
                return self._body

        err = FakeHTTPError()
        try:
            self.assertEqual(
                _http_error_reason(err),
                " failed to parse date field",
            )
        finally:
            err.close()

    def test_auth_login_roles_and_wazuh_queries_catalog(self):
        # Unauthenticated check when X-Arbiter-Auth-Enforce is set
        unauth = self.client.get("/api/tenants", headers={"X-Arbiter-Auth-Enforce": "1"})
        self.assertEqual(unauth.status_code, 401)

        # Login with default admin account
        login = self.client.post("/api/auth/login", json={"username": "admin", "password": "arbiter123"})
        self.assertEqual(login.status_code, 200, login.text)
        token = login.json()["token"]
        self.assertEqual(login.json()["user"]["role"], "admin")
        admin_headers = {"Authorization": f"Bearer {token}"}

        # Admin can create an analyst user
        created = self.client.post(
            "/api/auth/users",
            headers=admin_headers,
            json={"username": "soc_analyst", "password": "analystPass99", "role": "analyst", "display_name": "SOC L1"},
        )
        self.assertEqual(created.status_code, 200, created.text)
        usernames = [u["username"] for u in created.json()["users"]]
        self.assertIn("soc_analyst", usernames)

        # Login as analyst
        analyst_login = self.client.post("/api/auth/login", json={"username": "soc_analyst", "password": "analystPass99"})
        self.assertEqual(analyst_login.status_code, 200, analyst_login.text)
        analyst_token = analyst_login.json()["token"]
        analyst_headers = {"Authorization": f"Bearer {analyst_token}"}

        # Analyst cannot update settings, access database status, or manage users
        self.assertEqual(
            self.client.put("/api/settings", headers=analyst_headers, json={"ui": {"sidebar_default": "collapsed"}}).status_code,
            403,
        )
        self.assertEqual(
            self.client.get("/api/database", headers=analyst_headers).status_code,
            403,
        )
        self.assertEqual(
            self.client.get("/api/auth/users", headers=analyst_headers).status_code,
            403,
        )

        # Both analyst and admin can access and save Rumus Query Wazuh (Notepad & Snippets)
        pad_res = self.client.put(
            "/api/wazuh-queries",
            headers=analyst_headers,
            json={"notepad": "not (\"payload_1\" or \"payload_2\")"},
        )
        self.assertEqual(pad_res.status_code, 200, pad_res.text)
        self.assertEqual(pad_res.json()["notepad"], "not (\"payload_1\" or \"payload_2\")")
        self.assertEqual(pad_res.json()["updated_by"], "soc_analyst")

        save_q = self.client.post(
            "/api/wazuh-queries",
            headers=analyst_headers,
            json={"title": "Cek Path Traversal", "content": "not ([payload])", "category": "Web"},
        )
        self.assertEqual(save_q.status_code, 200, save_q.text)
        queries = save_q.json()["queries"]
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0]["created_by"], "soc_analyst")
        self.assertEqual(queries[0]["content"], "not ([payload])")
        self.assertEqual(save_q.json()["notepad"], "not (\"payload_1\" or \"payload_2\")")


if __name__ == "__main__":
    unittest.main()
