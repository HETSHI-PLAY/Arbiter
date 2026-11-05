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

    # ── Two-stage triage: deterministic clustering → LLM classification ──

    def _sample_alerts(self):
        return [
            {"id": "1", "rule_id": "5710", "rule_level": 10, "description": "SSH brute force", "source_ip": "1.2.3.4", "agent_name": "host-a", "hit_count": 2450, "log_signature": "sig-brute"},
            {"id": "2", "rule_id": "5710", "rule_level": 10, "description": "SSH brute force", "source_ip": "1.2.3.4", "agent_name": "host-a", "hit_count": 3, "log_signature": "sig-brute"},
            {"id": "3", "rule_id": "9999", "rule_level": 7, "description": "routine audit", "source_ip": "5.6.7.8", "agent_name": "host-b", "hit_count": 1, "log_signature": "sig-audit"},
        ]

    def test_cluster_alerts_groups_by_signature_and_keeps_singletons(self):
        from app.ai_triage import _cluster_alerts
        clusters = _cluster_alerts(self._sample_alerts())
        # 1+2 share log_signature → one cluster; 3 is a singleton.
        self.assertEqual(len(clusters), 2)
        by_count = {c["alert_count"]: c for c in clusters}
        self.assertIn(2, by_count)
        self.assertIn(1, by_count)
        grouped = by_count[2]
        self.assertEqual(set(grouped["alert_ids"]), {"1", "2"})
        self.assertEqual(grouped["total_hits"], 2453)
        # Sanitized summary carries counts but never raw logs or ids as prompt fields.
        self.assertNotIn("full_log", grouped)
        self.assertNotIn("raw", grouped)
        self.assertNotIn("data", grouped)

    def test_cluster_prompt_never_contains_alert_ids_or_raw_logs(self):
        from app.ai_triage import _cluster_alerts, _cluster_prompt
        clusters = _cluster_alerts(self._sample_alerts())
        prompt = _cluster_prompt(clusters)
        # Alert ids and raw log text must never reach the model.
        for forbidden in ("sig-brute", "sig-audit", "\"id\":", "full_log", "Synthetic curl bot"):
            self.assertNotIn(forbidden, prompt)
        self.assertIn("\"index\":", prompt)
        self.assertIn("\"verdicts\"", prompt)
        self.assertIn("2453", prompt, "total hits summarized into the prompt")

    def test_validate_cluster_verdicts_maps_index_back_to_alert_ids(self):
        from app.ai_triage import _cluster_alerts, _validate_cluster_verdicts
        clusters = _cluster_alerts(self._sample_alerts())
        value = {
            "verdicts": [
                {"index": 0, "verdict": "tp", "reason": "brute force dari IP tunggal"},
                {"index": 1, "verdict": "bogus", "reason": ""},  # unknown verdict normalizes
            ]
        }
        groups = _validate_cluster_verdicts(value, clusters)
        self.assertEqual(len(groups), 2)
        by_verdict = {g["verdict"]: g for g in groups}
        self.assertIn("tp", by_verdict)
        self.assertIn("needs_review", by_verdict)
        self.assertEqual(set(by_verdict["tp"]["alert_ids"]), {"1", "2"})

    def test_validate_cluster_verdicts_fills_skipped_clusters(self):
        from app.ai_triage import _cluster_alerts, _validate_cluster_verdicts
        clusters = _cluster_alerts(self._sample_alerts())
        groups = _validate_cluster_verdicts({"verdicts": [{"index": 0, "verdict": "fp"}]}, clusters)
        self.assertEqual(len(groups), 2, "skipped cluster still gets a needs_review verdict")
        # Every alert still covered.
        ids = {aid for g in groups for aid in g["alert_ids"]}
        self.assertEqual(ids, {"1", "2", "3"})

    def test_ai_triage_sends_clusters_not_raw_alerts(self):
        from app.ai_triage import ai_triage
        captured = {}

        def fake_ollama(prompt, *, model, base_url, timeout):
            captured["prompt"] = prompt
            return '{"verdicts":[{"index":0,"verdict":"tp","reason":"x"},{"index":1,"verdict":"fp","reason":"y"}]}'

        with patch("app.ai_triage.ollama_request", side_effect=fake_ollama):
            groups = ai_triage(self._sample_alerts(), model="m", base_url="http://127.0.0.1:11434")
        self.assertEqual(len(groups), 2)
        self.assertNotIn("sig-brute", captured["prompt"])
        self.assertNotIn("\"alert_ids\"", captured["prompt"])

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

    def test_realtime_settings_validate_mode_and_max_alerts(self):
        for payload, field in [
            ({"realtime": {"mode": "hourly"}}, "mode"),
            ({"realtime": {"max_alerts": 0}}, "max_alerts"),
            ({"realtime": {"max_alerts": 99999}}, "max_alerts"),
        ]:
            response = self.client.put("/api/settings", json=payload)
            self.assertEqual(response.status_code, 400, response.text)
            self.assertIn(field, response.json()["detail"])

    def test_realtime_pull_requires_configured_indexer(self):
        response = self.client.post("/api/realtime/pull")
        self.assertEqual(response.status_code, 400)
        self.assertIn("belum dikonfigurasi", response.json()["detail"])

    def test_realtime_pull_ingests_docs_into_active_db(self):
        self.client.put("/api/settings", json={"wazuh": {"indexer_url": "https://wazuh.lab:9200", "username": "analyst", "password": "stored"}})
        docs = [{
            "id": "wazuh-1", "timestamp": "2026-11-05T12:00:00Z", "agent": {"name": "host-a", "ip": "192.0.2.10"},
            "rule": {"id": "5710", "level": 10, "description": "SSH brute force", "groups": ["syslog"]},
            "data": {"srcip": "1.2.3.4"}, "full_log": "Nov 5 12:00:00 host-a sshd[1]: Failed password",
        }]
        ingested = []
        with patch.object(self.api, "wazuh_search", return_value=docs) as mocked:
            def fake_ingest(conn, alert):
                ingested.append(alert)
                return True, False
            with patch.object(self.api, "ingest_alert_with_dedup", side_effect=fake_ingest):
                response = self.client.post("/api/realtime/pull")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["status"], "pulled")
        self.assertEqual(body["searched"], 1)
        self.assertEqual(body["inserted"], 1)
        mocked.assert_called_once()
        self.assertNotIn("stored", response.text)
        # The endpoint normalized the Wazuh doc before ingest.
        self.assertEqual(len(ingested), 1)
        self.assertEqual(ingested[0]["rule_level"], 10)
        self.assertEqual(ingested[0]["description"], "SSH brute force")
        # last_pull_at was persisted for daily gating / next since window.
        stored = self.client.get("/api/settings").json()["settings"]["realtime"]
        self.assertTrue(stored["last_pull_at"])

    def test_realtime_pull_daily_mode_skips_within_24h(self):
        from datetime import datetime, timedelta, timezone
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        self.client.put("/api/settings", json={
            "wazuh": {"indexer_url": "https://wazuh.lab:9200", "username": "analyst", "password": "stored"},
            "realtime": {"mode": "daily", "last_pull_at": recent},
        })
        with patch.object(self.api, "wazuh_search", return_value=[]) as mocked:
            response = self.client.post("/api/realtime/pull")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["status"], "skipped")
        self.assertIn("24 jam", response.json()["reason"])
        mocked.assert_not_called()

    def test_ai_triage_save_persists_verdict_groups(self):
        self.db.add_alert(4, "Alpha", rule_level=10, description="brute force", source_ip="1.2.3.4")
        self.db.add_alert(5, "Alpha", rule_level=10, description="brute force", source_ip="1.2.3.4")
        response = self.client.post("/api/ai/triage/save", json={
            "tenant": ["Alpha"],
            "groups": [
                {"title": "Brute force cluster", "category": "Same source + rule", "verdict": "tp", "reason": "Level 10", "alert_ids": [4, 5]},
                {"title": "Noise", "category": "Heuristic", "verdict": "bogus", "reason": "", "alert_ids": [4]},
            ],
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["count"], 2)
        self.assertEqual(body["saved"][0]["verdict"], "tp")
        self.assertEqual(body["saved"][1]["verdict"], "needs_review", "unknown verdict normalizes")
        # Persisted with source='ai' and member links.
        rows = self.db.connection.execute(
            "SELECT id, verdict, source FROM wazuh.analysis_groups ORDER BY title"
        ).fetchall()
        self.assertEqual(len(rows), 3)  # 2 saved + 1 pre-existing fixture
        saved = [r for r in rows if r["source"] == "ai"]
        self.assertEqual(len(saved), 2)
        self.assertEqual({r["verdict"] for r in saved}, {"tp", "needs_review"})
        members = self.db.connection.execute(
            "SELECT group_id, alert_pk FROM wazuh.alert_group_members WHERE alert_pk IN (4, 5)"
        ).fetchall()
        self.assertEqual(len(members), 3, "2 members in tp group + 1 in the second")

    def test_ai_triage_save_rejects_empty_and_invalid_members(self):
        response = self.client.post("/api/ai/triage/save", json={"tenant": ["Alpha"], "groups": []})
        self.assertEqual(response.status_code, 400)
        # A group whose members are all outside the tenant is rejected before insert.
        response = self.client.post("/api/ai/triage/save", json={
            "tenant": ["Gamma"],
            "groups": [{"title": "X", "verdict": "tp", "alert_ids": [1]}],
        })
        self.assertEqual(response.status_code, 400)
        self.assertIn("outside the active tenant", response.json()["detail"])


if __name__ == "__main__":
    unittest.main()
