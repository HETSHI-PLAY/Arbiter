"""Isolated synthetic contract tests for Arbiter statistics and triage summary endpoints.

Uses SyntheticDB in-memory SQLite only; never touches production database or .env.
"""
from __future__ import annotations

import json
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient

from tests.test_ui_api import load_isolated_api, SyntheticDB, GROUP, OTHER_GROUP


class StatsEndpointContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.api = load_isolated_api()

    def setUp(self):
        self.db = SyntheticDB()
        self.db_patch = patch.object(self.api, "get_db", self.db.session)
        self.db_patch.start()
        self.client = TestClient(self.api.app)

        # Populate a diverse set of synthetic alerts across multiple tenants, rules, and HTTP fields
        # Current db has pk 1 (Alpha, hit_count 3), pk 2 (Beta, hit_count 3), pk 3 (Alpha, hit_count 1, reviewed)
        # Add additional synthetic alerts:
        self.db.add_alert(
            10, "Alpha",
            alert_id="syn-10", timestamp="2026-01-01T10:05:00Z",
            agent_name="host-web-1", rule_id="1001", rule_level=12,
            description="SQL injection probe", source_ip="203.0.113.5",
            hit_count=5, is_reviewed=False,
            parsed_details='{"status":"403","path":"/login.php","referer":"http://evil.com","ua":"sqlmap/1.0","log_type":"http"}',
        )
        self.db.add_alert(
            11, "Alpha",
            alert_id="syn-11", timestamp="2026-01-01T10:15:00Z",
            agent_name="host-web-1", rule_id="1001", rule_level=12,
            description="SQL injection probe", source_ip="203.0.113.5",
            hit_count=10, is_reviewed=False,
            parsed_details='{"status":"403","path":"/admin.php","referer":"http://evil.com","ua":"sqlmap/1.0","log_type":"http"}',
        )
        self.db.add_alert(
            12, "Alpha",
            alert_id="syn-12", timestamp="2026-01-01T11:20:00Z",
            agent_name="host-web-2", rule_id="2002", rule_level=7,
            description="Suspicious user agent", source_ip="198.51.100.22",
            hit_count=2, is_reviewed=True,
            parsed_details='{"status":"200","path":"/index.html","referer":"","ua":"curl/7.68.0","log_type":"http"}',
        )
        self.db.add_alert(
            13, "Beta",
            alert_id="syn-13", timestamp="2026-01-01T12:00:00Z",
            agent_name="host-db-1", rule_id="3003", rule_level=5,
            description="Database login failure", source_ip="192.0.2.99",
            hit_count=1, is_reviewed=False,
            parsed_details='{"log_type":"syslog"}',
        )

    def tearDown(self):
        self.client.close()
        self.db_patch.stop()
        self.db.connection.close()

    def test_stats_validates_pivot_by_against_whitelist(self):
        # Invalid pivot_by must fail with 422 before SQL
        res = self.client.get("/api/stats", params={"pivot_by": "invalid_column"})
        self.assertEqual(res.status_code, 422, res.text)
        self.assertIn("pivot_by", res.json()["detail"].lower())

    def test_stats_validates_top_n_bounds(self):
        for bad_top in (0, -1, 1001, 2000):
            res = self.client.get("/api/stats", params={"top_n": bad_top})
            self.assertEqual(res.status_code, 422, res.text)

    def test_stats_validates_pattern_pivot_requires_literal_pattern(self):
        res = self.client.get("/api/stats", params={"pivot_by": "pattern"})
        self.assertEqual(res.status_code, 422, res.text)
        self.assertIn("pattern", res.json()["detail"].lower())

        long_pattern = "x" * 121
        res2 = self.client.get("/api/stats", params={"pivot_by": "pattern", "pattern": long_pattern})
        self.assertEqual(res2.status_code, 422, res2.text)

    def test_stats_pivot_by_rule_description_alerts_metric(self):
        res = self.client.get("/api/stats", params={"tenant": "Alpha", "pivot_by": "rule_description", "metric": "alerts"})
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual(data["pivot_by"], "rule_description")
        self.assertEqual(data["metric"], "alerts")
        self.assertEqual(data["total"], 5)  # 5 alerts in Alpha: pk 1, 3, 10, 11, 12
        items = data["items"]
        self.assertTrue(len(items) > 0)
        # Sum of items + other_count == total
        item_total = sum(item["count"] for item in items) + data["other_count"]
        self.assertEqual(item_total, data["total"])
        # Check rule 1001 description has count 2
        sqli_item = next((it for it in items if it["key"] == "SQL injection probe"), None)
        self.assertIsNotNone(sqli_item)
        self.assertEqual(sqli_item["count"], 2)

    def test_stats_pivot_by_rule_description_events_metric(self):
        res = self.client.get("/api/stats", params={"tenant": "Alpha", "pivot_by": "rule_description", "metric": "events"})
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual(data["metric"], "events")
        # pk 1: 3, pk 3: 1, pk 10: 5, pk 11: 10, pk 12: 2 -> total hits = 21
        self.assertEqual(data["total"], 21)
        sqli_item = next((it for it in data["items"] if it["key"] == "SQL injection probe"), None)
        self.assertIsNotNone(sqli_item)
        self.assertEqual(sqli_item["count"], 15)  # 5 + 10

    def test_stats_pivot_distribution_and_other_bucket(self):
        # All distinct categories have their own individual item, other_count is strictly 0
        res = self.client.get("/api/stats", params={"tenant": "Alpha", "pivot_by": "source_ip"})
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual(data["other_count"], 0)
        self.assertEqual(data["other_percentage"], 0.0)
        self.assertEqual(len(data["other_items"]), 0)
        self.assertEqual(sum(it["count"] for it in data["items"]), data["total"])
        self.assertNotIn("Lainnya", [it["key"] for it in data["items"]])

    def test_stats_pivot_by_severity(self):
        res = self.client.get("/api/stats", params={"tenant": "Alpha", "pivot_by": "severity"})
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        keys = {it["key"].lower() for it in data["items"]}
        # In Alpha we have level 12 (high, 12-14), level 7 (medium, 7-11)
        self.assertIn("high", keys)
        self.assertIn("medium", keys)

    def test_stats_pivot_by_parsed_http_fields(self):
        for pivot in ("http_status", "url_path", "referer", "user_agent"):
            with self.subTest(pivot=pivot):
                res = self.client.get("/api/stats", params={"tenant": "Alpha", "pivot_by": pivot})
                self.assertEqual(res.status_code, 200, res.text)
                data = res.json()
                self.assertEqual(data["pivot_by"], pivot)
                self.assertIn("items", data)
                self.assertEqual(sum(it["count"] for it in data["items"]) + data["other_count"], data["total"])

    def test_stats_literal_pattern_matching(self):
        res = self.client.get("/api/stats", params={"tenant": "Alpha", "pivot_by": "pattern", "pattern": "sqlmap"})
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        match_item = next((it for it in data["items"] if "cocok" in it["key"].lower() and "tidak" not in it["key"].lower()), None)
        self.assertIsNotNone(match_item)
        self.assertEqual(match_item["count"], 2)  # syn-10 and syn-11 have sqlmap in parsed_details

    def test_stats_respects_tenant_isolation(self):
        res_alpha = self.client.get("/api/stats", params={"tenant": "Alpha", "pivot_by": "tenant"})
        self.assertEqual(res_alpha.status_code, 200)
        self.assertEqual(res_alpha.json()["total"], 5)
        self.assertEqual(len(res_alpha.json()["items"]), 1)
        self.assertEqual(res_alpha.json()["items"][0]["key"], "Alpha")

        res_multi = self.client.get("/api/stats", params=[("tenant", "Alpha"), ("tenant", "Beta"), ("pivot_by", "tenant")])
        self.assertEqual(res_multi.status_code, 200)
        self.assertEqual(res_multi.json()["total"], 7)  # 5 in Alpha + 2 in Beta

    def test_triage_summary_matches_filtered_alerts_count(self):
        # Test summary matches list_alerts total
        for tenant_param in ({"tenant": "Alpha"}, {"tenant": "Beta"}, {"tenant": "all"}):
            with self.subTest(tenant=tenant_param):
                alerts_res = self.client.get("/api/alerts", params=tenant_param)
                summary_res = self.client.get("/api/triage/summary", params=tenant_param)
                self.assertEqual(alerts_res.status_code, 200)
                self.assertEqual(summary_res.status_code, 200, summary_res.text)

                alerts_total = alerts_res.json()["total"]
                summary_data = summary_res.json()
                self.assertEqual(summary_data["alerts"], alerts_total)
                self.assertIsInstance(summary_data["events"], int)
                self.assertGreaterEqual(summary_data["events"], alerts_total)
                self.assertIn("severity", summary_data)
                self.assertIn("unique_source_ips", summary_data)
                self.assertIn("unique_agents", summary_data)
                self.assertIn("incident_cases", summary_data)
                self.assertIn("time_range", summary_data)
                self.assertIn("top_rule", summary_data)

    def test_triage_summary_top_rule_and_severity_breakdown(self):
        res = self.client.get("/api/triage/summary", params={"tenant": "Alpha"})
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["severity"]["high"], 2)  # syn-10 and syn-11 (level 12 = High 12-14)
        top_rule = data["top_rule"]
        self.assertIsNotNone(top_rule)
        self.assertEqual(top_rule["rule_id"], "1001")
        self.assertEqual(top_rule["count"], 2)

    def test_stats_secondary_pivot_stacked_data(self):
        res = self.client.get("/api/stats", params={
            "tenant": "Alpha",
            "pivot_by": "rule_description",
            "secondary_pivot": "source_ip",
        })
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertIn("secondary_pivot", data)
        self.assertEqual(data["secondary_pivot"], "source_ip")
        self.assertIn("secondary_distribution", data)

    def test_stats_above_average_spike_marker(self):
        res = self.client.get("/api/stats", params={
            "tenant": "Alpha",
            "bucket": "hour",
        })
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertIn("time_series", data)
        # Check that time series elements have above_average boolean
        for bucket in data["time_series"]:
            self.assertIn("above_average", bucket)

    def test_stats_time_preset_24h_filters_old_alerts(self):
        # Alert with timestamp in the future/recent vs old
        # Current synthetic alerts are 2026-01-01 (older than 24h from now)
        # Testing with time_preset=24h should return 0 alerts because 2026-01-01 is past
        res = self.client.get("/api/stats", params={
            "tenant": "Alpha",
            "time_preset": "24h",
        })
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["total"], 0)

    def test_stats_url_path_extracts_from_data_and_cleans_query(self):
        # Alert where url is only in data JSON, not in parsed_details
        self.db.add_alert(
            99, "Alpha",
            alert_id="syn-99", timestamp="2026-01-01T12:30:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            data='{"url":"/wp-login.php?action=lostpassword","id":"400"}',
            parsed_details='{"log_type":"http"}',
        )
        self.db.add_alert(
            101, "Alpha",
            alert_id="syn-101", timestamp="2026-01-01T12:31:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            data='{"url":"/?author=1","id":"400"}',
            parsed_details='{"log_type":"http"}',
        )
        self.db.add_alert(
            102, "Alpha",
            alert_id="syn-102", timestamp="2026-01-01T12:32:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            data='{"url":"/?rest_route=/batch/v1","id":"400"}',
            parsed_details='{"log_type":"http"}',
        )
        self.db.add_alert(
            103, "Alpha",
            alert_id="syn-103", timestamp="2026-01-01T12:33:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            data='{"url":"/","id":"400"}',
            parsed_details='{"log_type":"http"}',
        )
        self.db.add_alert(
            104, "Alpha",
            alert_id="syn-104", timestamp="2026-01-01T12:34:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            data='{"url":"/index.php/sebatik/article/view/100?id=1","id":"400"}',
            parsed_details='{"log_type":"http"}',
        )

        res = self.client.get("/api/stats", params={
            "tenant": "Alpha",
            "pivot_by": "url_path",
            "top_n": 50,
        })
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        keys = {it["key"] for it in data["items"]}
        self.assertIn("/wp-login.php", keys)
        self.assertIn("/login.php", keys)
        self.assertIn("/admin.php", keys)
        self.assertIn("/index.html", keys)
        # Root probe query strings are preserved individually
        self.assertIn("/?author=1", keys)
        self.assertIn("/?rest_route=/batch/v1", keys)
        self.assertIn("/", keys)
        # Deep application endpoints still clean query parameters
        self.assertIn("/index.php/sebatik/article/view/100", keys)
        self.assertNotIn("/index.php/sebatik/article/view/100?id=1", keys)

    def test_alerts_endpoint_respects_facet_drilldown(self):
        # syn-10 & syn-11 have description 'SQL injection probe'
        res = self.client.get("/api/alerts", params={
            "tenant": "Alpha",
            "facet": "rule_description",
            "facet_value": "SQL injection probe",
        })
        self.assertEqual(res.status_code, 200, res.text)
        items = res.json()["items"]
        self.assertEqual(len(items), 2)
        for it in items:
            self.assertEqual(it["description"], "SQL injection probe")

    def test_alerts_and_stats_endpoint_respects_dual_facet_drilldown(self):
        # With both primary facet and secondary facet, only syn-10 matches /login.php
        res = self.client.get("/api/alerts", params={
            "tenant": "Alpha",
            "facet": "rule_description",
            "facet_value": "SQL injection probe",
            "secondary_facet": "url_path",
            "secondary_facet_value": "/login.php",
        })
        self.assertEqual(res.status_code, 200, res.text)
        items = res.json()["items"]
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["alert_id"], "syn-10")

        # Stats returns secondary_breakdown when primary facet is active
        res_stats = self.client.get("/api/stats", params={
            "tenant": "Alpha",
            "pivot_by": "rule_description",
            "secondary_pivot": "url_path",
            "facet": "rule_description",
            "facet_value": "SQL injection probe",
        })
        self.assertEqual(res_stats.status_code, 200, res_stats.text)
        sb = res_stats.json().get("secondary_breakdown")
        self.assertIsNotNone(sb)
        sb_keys = {it["key"] for it in sb}
        self.assertEqual(sb_keys, {"/login.php", "/admin.php"})

    def test_facet_alert_ids_endpoint(self):
        # Resolve IDs for single secondary category
        res = self.client.post("/api/stats/facet-alert-ids", json={
            "tenant": ["Alpha"],
            "facet": "rule_description",
            "facet_value": "SQL injection probe",
            "secondary_facet": "url_path",
            "secondary_facet_values": ["/login.php"],
        })
        self.assertEqual(res.status_code, 200, res.text)
        self.assertEqual(res.json()["alert_pks"], [10])
        self.assertEqual(res.json()["total"], 1)

        # Resolve IDs for multiple secondary categories at once
        res_multi = self.client.post("/api/stats/facet-alert-ids", json={
            "tenant": ["Alpha"],
            "facet": "rule_description",
            "facet_value": "SQL injection probe",
            "secondary_facet": "url_path",
            "secondary_facet_values": ["/login.php", "/admin.php"],
        })
        self.assertEqual(res_multi.status_code, 200, res_multi.text)
        self.assertEqual(res_multi.json()["alert_pks"], [10, 11])
        self.assertEqual(res_multi.json()["total"], 2)

    def test_facet_alert_ids_spotter_mode_isolates_individual_alerts(self):
        self.db.add_alert(
            20, "Alpha",
            alert_id="syn-20", timestamp="2026-01-01T12:30:00Z",
            agent_name="host-web-1", rule_id="31101", rule_level=5,
            description="Web server 400 error code.", source_ip="203.0.113.88",
            hit_count=1, is_reviewed=False,
            parsed_details='{"status":"400","path":"/index.php/sebatik","method":"GET","ua":"Mozilla/5.0","log_type":"http"}',
        )
        self.db.add_alert(
            21, "Alpha",
            alert_id="syn-21", timestamp="2026-01-01T12:35:00Z",
            agent_name="host-web-1", rule_id="31101", rule_level=5,
            description="Web server 400 error code.", source_ip="114.12.10.151",
            hit_count=1, is_reviewed=False,
            parsed_details='{"status":"400","path":"/index.php/sebatik","method":"POST","ua":"Mozilla/5.0","log_type":"http"}',
            raw='{"full_log":"172.18.0.2:80 114.12.10.151 - - \\"POST /index.php/sebatik HTTP/1.0\\" 400 482"}',
        )

        # Alerts pk 20 (GET) and pk 21 (POST) both have url_path '/index.php/sebatik'
        # spotter_mode='all' returns both [20, 21]
        res_all = self.client.post("/api/stats/facet-alert-ids", json={
            "tenant": ["Alpha"],
            "secondary_facet": "url_path",
            "secondary_facet_values": ["/index.php/sebatik"],
            "spotter_mode": "all",
        })
        self.assertEqual(res_all.status_code, 200, res_all.text)
        self.assertEqual(set(res_all.json()["alert_pks"]), {20, 21})

        # spotter_mode='benign' returns ONLY pk 20 (the legitimate GET) and excludes pk 21 (the POST)
        res_benign = self.client.post("/api/stats/facet-alert-ids", json={
            "tenant": ["Alpha"],
            "secondary_facet": "url_path",
            "secondary_facet_values": ["/index.php/sebatik"],
            "spotter_mode": "benign",
        })
        self.assertEqual(res_benign.status_code, 200, res_benign.text)
        self.assertEqual(res_benign.json()["alert_pks"], [20])
        self.assertNotIn(21, res_benign.json()["alert_pks"])

        # spotter_mode='malicious' returns ONLY pk 21 (the malicious POST) and excludes pk 20
        res_malicious = self.client.post("/api/stats/facet-alert-ids", json={
            "tenant": ["Alpha"],
            "secondary_facet": "url_path",
            "secondary_facet_values": ["/index.php/sebatik"],
            "spotter_mode": "malicious",
        })
        self.assertEqual(res_malicious.status_code, 200, res_malicious.text)
        self.assertEqual(res_malicious.json()["alert_pks"], [21])
        self.assertNotIn(20, res_malicious.json()["alert_pks"])

    def test_stats_secondary_facet_preserves_parent_scope_and_breakdown(self):
        self.db.add_alert(
            201, "Alpha",
            alert_id="syn-201", timestamp="2026-01-01T12:01:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            parsed_details='{"path": "/wp-content/styles.css", "log_type": "http"}',
        )
        self.db.add_alert(
            202, "Alpha",
            alert_id="syn-202", timestamp="2026-01-01T12:02:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            parsed_details='{"path": "/wp-content/styles.css", "log_type": "http"}',
        )
        self.db.add_alert(
            203, "Alpha",
            alert_id="syn-203", timestamp="2026-01-01T12:03:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            parsed_details='{"path": "/login.php", "log_type": "http"}',
        )
        self.db.add_alert(
            204, "Alpha",
            alert_id="syn-204", timestamp="2026-01-01T12:04:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            parsed_details='{"path": "/admin.php", "log_type": "http"}',
        )

        res = self.client.get("/api/stats", params={
            "tenant": "Alpha",
            "pivot_by": "rule_description",
            "secondary_pivot": "url_path",
            "facet": "rule_description",
            "facet_value": "Web server 400 error code.",
            "secondary_facet": "url_path",
            "secondary_facet_value": "/wp-content/styles.css",
        })
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertEqual(data["total"], 2)
        self.assertIn("parent_total", data)
        self.assertEqual(data["parent_total"], 4)
        self.assertIn("secondary_percentage_of_parent", data)
        self.assertEqual(data["secondary_percentage_of_parent"], 50.0)
        breakdown_keys = [it["key"] for it in data["secondary_breakdown"]]
        self.assertIn("/login.php", breakdown_keys)
        self.assertIn("/admin.php", breakdown_keys)
        self.assertIn("/wp-content/styles.css", breakdown_keys)
        # Check percentage in breakdown table items
        wp_item = next(it for it in data["secondary_breakdown"] if it["key"] == "/wp-content/styles.css")
        self.assertEqual(wp_item["count"], 2)
        self.assertEqual(wp_item["percentage"], 50.0)

    def test_stats_primary_facet_computes_percentage_of_workspace_total(self):
        # When primary facet is applied alone, backend must compute its percentage of workspace total
        self.db.add_alert(
            301, "Alpha",
            alert_id="syn-301", timestamp="2026-01-01T12:01:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            parsed_details='{"path": "/a", "log_type": "http"}',
        )
        self.db.add_alert(
            302, "Alpha",
            alert_id="syn-302", timestamp="2026-01-01T12:02:00Z",
            rule_id="31101", rule_level=5,
            description="Web server 400 error code.",
            parsed_details='{"path": "/b", "log_type": "http"}',
        )

        res = self.client.get("/api/stats", params={
            "tenant": "Alpha",
            "pivot_by": "rule_description",
            "facet": "rule_description",
            "facet_value": "Web server 400 error code.",
        })
        self.assertEqual(res.status_code, 200, res.text)
        data = res.json()
        self.assertIn("primary_percentage_of_total", data)
        self.assertIn("workspace_total", data)
        self.assertGreater(data["workspace_total"], 0)
        expected_pct = round((data["parent_total"] / data["workspace_total"] * 100.0), 2)
        self.assertEqual(data["primary_percentage_of_total"], expected_pct)


if __name__ == "__main__":
    unittest.main()
