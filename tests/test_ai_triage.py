"""AI Triage and Realtime count API contracts against synthetic in-memory SQLite only.

Follows the isolation strategy of tests/test_ui_api.py: app.database and
app.config are forbidden, and TestClient runs without lifespan so no real
database, .env, or network is ever touched. Ollama is never reached: the local
endpoint is mocked or refused before any socket is opened.
"""
from __future__ import annotations

import json
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
        for payload in ({"limit": 0}, {"limit": 10000}, {"min_rule_level": 99}, {"min_rule_level": -1}, {"min_rule_level": 12, "max_rule_level": 7}):
            response = self.client.post("/api/ai/triage", json=payload)
            self.assertEqual(response.status_code, 400, response.text)

    def test_ai_triage_supports_severity_ranges_7_11_12_14_15_plus_and_custom_limit(self):
        self.db.add_alert(9, "Alpha", rule_level=4, description="Low range alert")
        self.db.add_alert(10, "Alpha", rule_level=9, description="Medium range alert")
        self.db.add_alert(11, "Alpha", rule_level=13, description="High range alert")
        self.db.add_alert(12, "Alpha", rule_level=15, description="Critical range alert")
        low = self.client.post("/api/ai/triage", json={
            "tenant": ["Alpha"], "limit": 250, "min_rule_level": 0, "max_rule_level": 6, "review_status": "all",
        }).json()
        low_ids = {str(a["id"]) for a in low["alerts"]}
        self.assertEqual(low_ids, {"9"})

        med = self.client.post("/api/ai/triage", json={
            "tenant": ["Alpha"], "limit": 250, "min_rule_level": 7, "max_rule_level": 11, "review_status": "all",
        }).json()
        med_ids = {str(a["id"]) for a in med["alerts"]}
        self.assertIn("10", med_ids)
        self.assertNotIn("9", med_ids)
        self.assertNotIn("11", med_ids)
        self.assertNotIn("12", med_ids)

        high = self.client.post("/api/ai/triage", json={
            "tenant": ["Alpha"], "limit": 250, "min_rule_level": 12, "max_rule_level": 14, "review_status": "all",
        }).json()
        high_ids = {str(a["id"]) for a in high["alerts"]}
        self.assertEqual(high_ids, {"11"})

        crit = self.client.post("/api/ai/triage", json={
            "tenant": ["Alpha"], "limit": 250, "min_rule_level": 15, "review_status": "all",
        }).json()
        crit_ids = {str(a["id"]) for a in crit["alerts"]}
        self.assertEqual(crit_ids, {"12"})

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
            "base_url": "http://cloud.example.com:11434", "model": "hf.co/XHToken/Spark-X2.6-4B-GGUF:Q4_K_M",
        })
        self.assertEqual(response.status_code, 502)
        self.assertIn("loopback", response.json()["detail"].lower())

    def test_ai_settings_and_test_accept_private_lan_ip_and_strip_api_generate_path(self):
        model_tag = "hf.co/DavidAU/Qwen3.5-9B-The-Defiant-Fable-Uncensored-Heretic-NEO-IMATRIX-MAX-MTP-GGUF:Q4_K_M"
        saved = self.client.put("/api/settings", json={
            "ai": {
                "enabled": True,
                "base_url": "http://192.168.30.178:11434/api/generate",
                "model": model_tag,
                "timeout_seconds": 90,
            }
        })
        self.assertEqual(saved.status_code, 200, saved.text)
        ai_cfg = saved.json()["settings"]["ai"]
        self.assertEqual(ai_cfg["base_url"], "http://192.168.30.178:11434")
        self.assertEqual(ai_cfg["model"], model_tag)

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

    # ── IP-agnostic grouping: rotating source IPs collapse into one group ──

    def test_suggest_groups_collapses_rotating_source_ips_into_one_group(self):
        from app.core import suggest_groups
        # Same rule + same target host, three different source IPs. This is the
        # "attacker scans then changes IP" case: it must be ONE group, not three.
        alerts = [
            {"id": "a1", "rule_id": "31510", "rule_level": 10, "description": "Web scan", "source_ip": "1.2.3.4", "agent_name": "web-01", "hit_count": 1, "log_signature": "s1"},
            {"id": "a2", "rule_id": "31510", "rule_level": 10, "description": "Web scan", "source_ip": "5.6.7.8", "agent_name": "web-01", "hit_count": 1, "log_signature": "s2"},
            {"id": "a3", "rule_id": "31510", "rule_level": 10, "description": "Web scan", "source_ip": "9.9.9.9", "agent_name": "web-01", "hit_count": 1, "log_signature": "s3"},
        ]
        groups = suggest_groups(alerts)
        # The agent+rule group (now first priority) holds all three.
        host_groups = [g for g in groups if g["category"] == "Same agent + rule"]
        self.assertEqual(len(host_groups), 1)
        self.assertEqual(set(host_groups[0]["alert_ids"]), {"a1", "a2", "a3"})
        self.assertEqual(host_groups[0]["source_ips"], ["1.2.3.4", "5.6.7.8", "9.9.9.9"])
        self.assertEqual(host_groups[0]["alert_count"], 3)

    def test_suggest_groups_keeps_distinct_hosts_separate(self):
        from app.core import suggest_groups
        alerts = [
            {"id": "a1", "rule_id": "31510", "rule_level": 10, "description": "Web scan", "source_ip": "1.2.3.4", "agent_name": "web-01", "hit_count": 1, "log_signature": "s1"},
            {"id": "a2", "rule_id": "31510", "rule_level": 10, "description": "Web scan", "source_ip": "5.6.7.8", "agent_name": "web-01", "hit_count": 1, "log_signature": "s2"},
            {"id": "b1", "rule_id": "31510", "rule_level": 10, "description": "Web scan", "source_ip": "9.9.9.9", "agent_name": "web-02", "hit_count": 1, "log_signature": "s3"},
            {"id": "b2", "rule_id": "31510", "rule_level": 10, "description": "Web scan", "source_ip": "8.8.8.8", "agent_name": "web-02", "hit_count": 1, "log_signature": "s4"},
        ]
        groups = suggest_groups(alerts)
        host_groups = [g for g in groups if g["category"] == "Same agent + rule"]
        self.assertEqual(len(host_groups), 2, "different target hosts stay separate")
        self.assertEqual({g["alert_ids"][0] for g in host_groups}, {"a1", "b1"})

    def test_bulk_full_logs_returns_in_scope_logs_only(self):
        self.db.add_alert(4, "Alpha", rule_level=10, description="brute force", source_ip="1.2.3.4")
        self.db.add_alert(5, "Alpha", rule_level=10, description="brute force", source_ip="5.6.7.8")
        response = self.client.post("/api/alerts/full-logs", json={"tenant": ["Alpha"], "alert_ids": [4, 5]})
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["count"], 2)
        self.assertEqual({item["id"] for item in body["items"]}, {4, 5})
        for item in body["items"]:
            self.assertTrue(item["full_log"], "full_log must be populated from raw JSONB")

    def test_bulk_full_logs_rejects_out_of_scope_and_invalid(self):
        self.db.add_alert(4, "Alpha", rule_level=10, description="brute force", source_ip="1.2.3.4")
        response = self.client.post("/api/alerts/full-logs", params={"tenant": "Gamma"}, json={"alert_ids": [4]})
        self.assertEqual(response.status_code, 400)
        self.assertIn("outside the active tenant", response.json()["detail"])
        response = self.client.post("/api/alerts/full-logs", params={"tenant": "Alpha"}, json={"alert_ids": []})
        self.assertEqual(response.status_code, 400)
        response = self.client.post("/api/alerts/full-logs", params={"tenant": "Alpha"}, json={"alert_ids": ["bogus"]})
        self.assertEqual(response.status_code, 422)

    def test_group_by_rule_description_merges_multiple_agents_in_same_tenant_and_never_mixes_tenants(self):
        # Alpha has 2 different agents with the same rule description -> 1 group for Alpha.
        # Beta has the exact same rule description and agent -> must be a SEPARATE group for Beta.
        self.db.add_alert(20, "Alpha", rule_level=10, description="Multiple SSH authentication failures", source_ip="1.1.1.1", agent_name="alpha-web-01")
        self.db.add_alert(21, "Alpha", rule_level=10, description="Multiple SSH authentication failures", source_ip="2.2.2.2", agent_name="alpha-db-02")
        self.db.add_alert(22, "Beta", rule_level=10, description="Multiple SSH authentication failures", source_ip="1.1.1.1", agent_name="alpha-web-01")

        response = self.client.post("/api/ai/triage", json={
            "tenant": ["all"],
            "limit": 100,
            "min_rule_level": 7,
            "review_status": "all",
            "group_by": "rule_description",
        })
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["group_by"], "rule_description")
        alerts_by_id = {str(a["id"]): a for a in body["alerts"]}

        # Verify every single returned group belongs to strictly 1 tenant.
        for group in body["groups"]:
            tenants_in_group = {alerts_by_id[aid]["tenant"] for aid in group["alert_ids"]}
            self.assertEqual(len(tenants_in_group), 1, f"Group mixed multiple tenants: {group}")

        # Verify Alpha alerts 20 and 21 (different agents, same rule description) are in the same group.
        alpha_ssh_groups = [
            g for g in body["groups"]
            if {"20", "21"}.issubset(set(g["alert_ids"]))
        ]
        self.assertEqual(len(alpha_ssh_groups), 1)
        self.assertNotIn("22", alpha_ssh_groups[0]["alert_ids"])

    def test_ai_triage_save_rejects_multi_tenant_group(self):
        self.db.add_alert(30, "Alpha", rule_level=10, description="Shared rule", source_ip="1.2.3.4")
        self.db.add_alert(31, "Beta", rule_level=10, description="Shared rule", source_ip="1.2.3.4")
        response = self.client.post("/api/ai/triage/save", json={
            "tenant": ["all"],
            "groups": [
                {"title": "Illegal cross-tenant group", "category": "Rule description", "verdict": "tp", "reason": "test", "alert_ids": [30, 31]},
            ],
        })
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("2 tenant", response.json()["detail"])

    def test_ai_triage_persists_state_and_merges_new_alerts_with_1700_wib_cutoff(self):
        # 1. Before running AI Triage, GET /api/ai/triage indicates no saved state.
        initial = self.client.get("/api/ai/triage").json()
        self.assertFalse(initial["saved"])

        # 2. Add two alerts in tenant Alpha before 17:00 WIB on 2026-11-08 (10:00 WIB and 14:00 WIB).
        self.db.add_alert(
            40, "Alpha",
            timestamp="2026-11-08T10:00:00+07:00",
            rule_level=10,
            description="Wazuh rule: Brute force login",
            agent_name="alpha-agent-1",
        )
        self.db.add_alert(
            41, "Alpha",
            timestamp="2026-11-08T14:00:00+07:00",
            rule_level=10,
            description="Wazuh rule: Brute force login",
            agent_name="alpha-agent-2",
        )

        run_resp = self.client.post("/api/ai/triage", json={
            "tenant": ["Alpha"],
            "limit": 100,
            "min_rule_level": 7,
            "max_rule_level": 11,
            "review_status": "unreviewed",
            "group_by": "rule_description",
        })
        self.assertEqual(run_resp.status_code, 200, run_resp.text)

        # Save to incidents so an open AI incident case group exists for this 17:00 WIB window.
        groups_initial = run_resp.json()["groups"]
        brute_group = next(g for g in groups_initial if {"40", "41"}.issubset(set(g["alert_ids"])))
        self.assertEqual(brute_group["window_key"], "2026-11-08T17:00+07:00")
        save_resp = self.client.post("/api/ai/triage/save", json={
            "tenant": ["Alpha"],
            "groups": [brute_group],
        })
        self.assertEqual(save_resp.status_code, 200, save_resp.text)
        saved_case_id = save_resp.json()["saved"][0]["id"]
        self.assertFalse(save_resp.json()["saved"][0]["merged"])

        # 3. A new alert arrives at 16:30 WIB (still BEFORE 17:00 WIB on 2026-11-08),
        #    and another alert arrives at 17:05 WIB (AFTER 17:00 WIB cutoff on 2026-11-08).
        self.db.add_alert(
            42, "Alpha",
            timestamp="2026-11-08T16:30:00+07:00",
            rule_level=10,
            description="Wazuh rule: Brute force login",
            agent_name="alpha-agent-3",
        )
        self.db.add_alert(
            43, "Alpha",
            timestamp="2026-11-08T17:05:00+07:00",
            rule_level=10,
            description="Wazuh rule: Brute force login",
            agent_name="alpha-agent-1",
        )

        # 4. Reopening the AI Triage page (GET /api/ai/triage) returns the saved triage AND
        #    automatically merges alert 42 (<= 17:00 WIB) into the existing group, while
        #    placing alert 43 (> 17:00 WIB) into a separate new group!
        reopen = self.client.get("/api/ai/triage")
        self.assertEqual(reopen.status_code, 200, reopen.text)
        reopen_body = reopen.json()
        self.assertTrue(reopen_body["saved"])
        reopen_groups = reopen_body["result"]["groups"]

        pre_17_group = next(g for g in reopen_groups if "40" in g["alert_ids"])
        self.assertEqual(set(pre_17_group["alert_ids"]), {"40", "41", "42"})
        self.assertIn("42", pre_17_group.get("new_alert_ids", []))
        self.assertNotIn("43", pre_17_group["alert_ids"])
        self.assertEqual(pre_17_group["window_key"], "2026-11-08T17:00+07:00")
        self.assertEqual(pre_17_group.get("saved_group_id"), saved_case_id)

        post_17_group = next(g for g in reopen_groups if "43" in g["alert_ids"])
        self.assertEqual(set(post_17_group["alert_ids"]), {"43"})
        self.assertEqual(post_17_group["window_key"], "2026-11-09T17:00+07:00")

        # 5. Verify that alert 42 was also automatically linked into the existing open AI incident group,
        #    and saving both groups merges pre_17_group into saved_case_id while creating a new case for post_17_group.
        save_again = self.client.post("/api/ai/triage/save", json={
            "tenant": ["Alpha"],
            "groups": [pre_17_group, post_17_group],
        })
        self.assertEqual(save_again.status_code, 200, save_again.text)
        saved_items = save_again.json()["saved"]
        self.assertEqual(len(saved_items), 2)
        self.assertEqual(saved_items[0]["id"], saved_case_id)
        self.assertTrue(saved_items[0]["merged"])
        self.assertEqual(saved_items[0]["alert_count"], 3)
        self.assertNotEqual(saved_items[1]["id"], saved_case_id)
        self.assertFalse(saved_items[1]["merged"])
        self.assertEqual(saved_items[1]["alert_count"], 1)

    def test_apache_cgi_path_traversal_and_leakix_log_always_classified_as_tp(self):
        traversal_log = (
            '198.51.100.77 - - [08/Nov/2026:10:15:00 +0700] '
            '"GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts HTTP/1.1" '
            '400 487 "-" "Lkx-Apache2449TraversalPlugin/0.0.1 (+https://leakix.net/, +https://twitter.com/HaboubiAnis)"'
        )
        self.db.add_alert(
            60, "Alpha",
            timestamp="2026-11-08T10:15:00+07:00",
            rule_id="31101",
            rule_level=7,
            description="Web server 400 error code.",
            rule_groups='["web", "accesslog"]',
            raw=json.dumps({"full_log": traversal_log}),
            parsed_details=json.dumps({
                "log_type": "http",
                "method": "GET",
                "path": "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts",
                "status": "400",
                "ua": "Lkx-Apache2449TraversalPlugin/0.0.1 (+https://leakix.net/, +https://twitter.com/HaboubiAnis)",
            }),
        )

        # 1. Heuristic triage classifies as TP
        resp = self.client.post("/api/ai/triage", json={
            "tenant": ["Alpha"],
            "limit": 100,
            "min_rule_level": 0,
            "review_status": "all",
            "group_by": "rule_description",
        })
        self.assertEqual(resp.status_code, 200, resp.text)
        groups = resp.json()["groups"]
        target_group = next(g for g in groups if "60" in g["alert_ids"])
        self.assertEqual(target_group["verdict"], "tp")
        self.assertIn("Path Traversal", target_group["reason"])

        # 2. Even when local AI is enabled and the LLM falsely returns "fp" for the cluster,
        #    lock_tp prevents the exploit/traversal group from being downgraded to FP!
        self.client.put("/api/settings", json={"ai": {"enabled": True, "model": "qwen2.5:7b"}})
        fake_llm_fp = json.dumps({"verdicts": [{"index": 0, "verdict": "fp", "reason": "Hanya error 400 biasa"}, {"index": 1, "verdict": "fp", "reason": "Hanya error 400 biasa"}]})
        ai_fn = self.api.triage_with_fallback.__globals__["ai_triage"]
        with patch.dict(ai_fn.__globals__, {"ollama_request": Mock(return_value=fake_llm_fp)}):
            ai_resp = self.client.post("/api/ai/triage", json={
                "tenant": ["Alpha"],
                "limit": 100,
                "min_rule_level": 0,
                "review_status": "all",
                "group_by": "rule_description",
            })
        self.assertEqual(ai_resp.status_code, 200, ai_resp.text)
        self.assertEqual(ai_resp.json()["mode"], "local_ai")
        ai_group = next(g for g in ai_resp.json()["groups"] if "60" in g["alert_ids"])
        self.assertEqual(ai_group["verdict"], "tp")

    def test_alerts_and_triage_summary_filter_by_alert_ids(self):
        self.db.add_alert(70, "Alpha", rule_level=10, description="Related alert 1")
        self.db.add_alert(71, "Alpha", rule_level=10, description="Related alert 2")
        self.db.add_alert(72, "Alpha", rule_level=10, description="Unrelated alert 3")

        alerts_resp = self.client.get("/api/alerts", params={
            "tenant": "Alpha",
            "review_status": "all",
            "alert_ids": "70,71",
        })
        self.assertEqual(alerts_resp.status_code, 200, alerts_resp.text)
        body = alerts_resp.json()
        self.assertEqual(body["total"], 2)
        self.assertEqual({item["id"] for item in body["items"]}, {70, 71})

        summary_resp = self.client.get("/api/triage/summary", params={
            "tenant": "Alpha",
            "review_status": "all",
            "alert_ids": "70,71",
        })
        self.assertEqual(summary_resp.status_code, 200, summary_resp.text)
        self.assertEqual(summary_resp.json()["alerts"], 2)

    def test_realtime_pull_respects_custom_severity_and_resets_since_on_severity_change(self):
        self.client.put("/api/settings", json={
            "wazuh": {"indexer_url": "https://wazuh.lab:9200", "username": "analyst", "password": "stored"},
            "realtime": {"min_rule_level": 12, "max_rule_level": 14, "last_pull_at": "2026-11-08T10:00:00Z"},
        })
        saved_rt = self.client.get("/api/settings").json()["settings"]["realtime"]
        self.assertEqual(saved_rt["min_rule_level"], 12)
        self.assertEqual(saved_rt["max_rule_level"], 14)

        # Changing severity in settings without passing last_pull_at resets last_pull_at so new severity can be pulled
        updated_rt = self.client.put("/api/settings", json={
            "realtime": {"min_rule_level": 0, "max_rule_level": 6},
        }).json()["settings"]["realtime"]
        self.assertEqual(updated_rt["min_rule_level"], 0)
        self.assertEqual(updated_rt["max_rule_level"], 6)
        self.assertEqual(updated_rt["last_pull_at"], "")

        captured_kwargs = {}
        def fake_search(**kwargs):
            captured_kwargs.update(kwargs)
            return []

        with patch.object(self.api, "wazuh_search", side_effect=fake_search):
            pull_resp = self.client.post("/api/realtime/pull", json={"min_rule_level": 15, "max_rule_level": None})
        self.assertEqual(pull_resp.status_code, 200, pull_resp.text)
        self.assertEqual(captured_kwargs["min_rule_level"], 15)
        self.assertIsNone(captured_kwargs["max_rule_level"])
        self.assertEqual(pull_resp.json()["min_rule_level"], 15)
        self.assertIsNone(pull_resp.json()["max_rule_level"])


if __name__ == "__main__":
    unittest.main()
