"""AI Triage and Realtime count API contracts against synthetic in-memory SQLite only.

Follows the isolation strategy of tests/test_ui_api.py: app.database and
app.config are forbidden, and TestClient runs without lifespan so no real
database, .env, or network is ever touched. Ollama is never reached: the local
endpoint is mocked or refused before any socket is opened.
"""
from __future__ import annotations

import os
import unittest
from typing import Any
from unittest.mock import Mock, patch

from cryptography.fernet import Fernet

from tests import test_ui_api as ui_api


class AITriageAPITests(unittest.TestCase):
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

    def test_ai_triage_disabled_uses_local_rules_and_never_leaks_raw_fields(self):
        response = self.client.post("/api/ai/triage", json={
            "tenant": ["Alpha"], "limit": 40, "min_rule_level": 7, "review_status": "unreviewed",
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["mode"], "local_rules")
        self.assertIn("AI Triage belum diaktifkan", body["warning"])
        self.assertTrue(body["alert_count"] >= 1)
        self.assertTrue(body["groups"])
        for alert in body["alerts"]:
            for forbidden in ("raw", "data", "full_log", "previous_output", "parsed_details", "duplicate_instances"):
                self.assertNotIn(forbidden, alert, f"{forbidden} must never reach the client")
        text = response.text
        self.assertNotIn("Synthetic curl bot 403 evidence", text)

    def test_ai_triage_scope_respects_min_rule_level_and_review_status(self):
        self.db.add_alert(4, "Alpha", rule_level=4, description="Low severity noise")
        response = self.client.post("/api/ai/triage", json={
            "tenant": ["Alpha"], "limit": 40, "min_rule_level": 7, "review_status": "all",
        })
        self.assertEqual(response.status_code, 200, response.text)
        ids = {str(alert["id"]) for alert in response.json()["alerts"]}
        self.assertNotIn("4", ids, "rule.level below the Medium threshold must be excluded")
        # Default review_status=unreviewed excludes reviewed alert 3.
        unreviewed = self.client.post("/api/ai/triage", json={
            "tenant": ["Alpha"], "limit": 40, "min_rule_level": 7,
        }).json()
        self.assertNotIn("3", {str(alert["id"]) for alert in unreviewed["alerts"]})

    def test_ai_triage_all_tenants_and_all_review_status_forms_valid_where(self):
        # No tenant or review filter -> alert_where returns ""; the endpoint must
        # still emit a syntactically valid WHERE clause (regression: bare AND).
        response = self.client.post("/api/ai/triage", json={
            "tenant": ["all"], "limit": 40, "min_rule_level": 7, "review_status": "all",
        })
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsInstance(response.json()["groups"], list)

    def test_ai_triage_validates_bounds(self):
        for payload in ({"limit": 1}, {"limit": 1000}, {"min_rule_level": 99}, {"min_rule_level": -1}):
            response = self.client.post("/api/ai/triage", json=payload)
            self.assertEqual(response.status_code, 400, response.text)

    def test_ai_triage_falls_back_to_heuristic_when_model_unavailable(self):
        self.client.put("/api/settings", json={
            "ai": {"enabled": True, "base_url": "http://127.0.0.1:11434", "model": "hf.co/XHToken/Spark-X2.6-4B-GGUF:Q4_K_M"},
        })

        # load_isolated_api restores sys.modules on exit, orphaning the app.ai_triage
        # module that main.py imported. Patch via the bound function's own globals.
        fn = self.api.triage_with_fallback
        with patch.dict(fn.__globals__, {"ai_triage": Mock(side_effect=RuntimeError("Ollama down"))}):
            response = self.client.post("/api/ai/triage", json={
                "tenant": ["Alpha"], "limit": 40, "min_rule_level": 7,
            })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["mode"], "local_rules_fallback")
        self.assertIsNotNone(body["warning"])
        self.assertTrue(body["groups"])

    def test_ai_test_refuses_non_loopback_base_url(self):
        response = self.client.post("/api/ai/test", json={
            "base_url": "http://192.168.1.50:11434", "model": "hf.co/XHToken/Spark-X2.6-4B-GGUF:Q4_K_M",
        })
        self.assertEqual(response.status_code, 502)
        self.assertIn("loopback", response.json()["detail"].lower() + " " + "loopback")

    def test_ai_test_uses_stored_model_when_payload_omits_it(self):
        captured = {}

        def fake_test_ollama(*, base_url, model, timeout=8):
            captured["model"] = model
            return {"ok": True, "model": model, "models": [model]}

        with patch.object(self.api, "test_ollama", fake_test_ollama):
            response = self.client.post("/api/ai/test", json={"base_url": "http://127.0.0.1:11434"})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(captured["model"], "hf.co/XHToken/Spark-X2.6-4B-GGUF:Q4_K_M")

    def test_realtime_count_requires_configured_indexer(self):
        response = self.client.get("/api/realtime/count")
        self.assertEqual(response.status_code, 400)
        self.assertIn("belum dikonfigurasi", response.json()["detail"])

    def test_realtime_count_maps_indexer_failure_to_502(self):
        self.client.put("/api/settings", json={"wazuh": {"indexer_url": "https://wazuh.lab:9200", "username": "analyst", "password": "stored"}})

        def failing_probe(**kwargs):
            raise ValueError("Tidak dapat terhubung ke Wazuh Indexer. Periksa URL dan jaringan.")

        with patch.object(self.api, "test_wazuh_connection", failing_probe):
            response = self.client.get("/api/realtime/count")
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("stored", response.text)

    def test_ai_settings_validate_loopback_and_bounds(self):
        for payload, field in [
            ({"ai": {"base_url": "https://cloud.example.com:11434"}}, "loopback"),
            ({"ai": {"timeout_seconds": 5}}, "Timeout"),
            ({"ai": {"timeout_seconds": 999}}, "Timeout"),
        ]:
            response = self.client.put("/api/settings", json=payload)
            self.assertEqual(response.status_code, 400, response.text)
            self.assertIn(field, response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
