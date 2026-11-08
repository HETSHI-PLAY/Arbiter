"""Synthetic contract tests for deterministic Wazuh read/classify/correlate logic.

No dataset rows, production alerts, database, or network are used.
"""

from __future__ import annotations

import unittest

from app.core import normalize_alert
from app.wazuh_intel import (
    build_attack_chains,
    classify_alert,
    correlate_alerts,
    extract_active_response,
)


def _active_response(origin_id: str = "origin-1", command: str = "add") -> dict:
    origin = {
        "id": origin_id,
        "timestamp": "2026-11-07T10:00:00Z",
        "rule": {
            "id": "5710",
            "level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "groups": ["syslog", "sshd", "authentication_failed", "invalid_login"],
        },
        "agent": {"name": "host-a", "ip": "192.0.2.5"},
        "data": {"srcip": "192.0.2.10", "srcuser": "nobody"},
        "full_log": "Nov  7 10:00:00 host-a sshd[1]: Invalid user nobody from 192.0.2.10",
    }
    return {
        "id": "response-1",
        "alert_id": "response-1",
        "timestamp": "2026-11-07T10:00:01Z",
        "agent_name": "host-a",
        "rule_id": "651",
        "rule_level": 3,
        "description": "Host Blocked by firewall-drop Active Response",
        "rule_groups": ["ossec", "active_response"],
        "source_ip": "192.0.2.10",
        "data": {
            "command": command,
            "srcip": "192.0.2.10",
            "parameters": {"alert": origin},
        },
        "raw": {"program": "active-response/bin/firewall-drop"},
        "full_log": "2026/11/07 10:00:01 active-response/bin/firewall-drop: "
        '{"command":"add","parameters":{"alert":{"id":"origin-1"}}}',
    }


class ActiveResponseReadTests(unittest.TestCase):
    def test_reads_structured_nested_origin_alert(self):
        origin = extract_active_response(_active_response())
        self.assertTrue(origin["is_active_response"])
        self.assertEqual(origin["command"], "add")
        self.assertEqual(origin["origin"]["alert_id"], "origin-1")
        self.assertEqual(origin["origin"]["rule_id"], "5710")
        self.assertEqual(origin["origin"]["source_ip"], "192.0.2.10")
        self.assertEqual(origin["origin"]["agent_name"], "host-a")

    def test_reads_json_payload_from_full_log_when_data_is_missing(self):
        alert = {
            "rule_id": "651",
            "rule_level": 3,
            "rule_groups": ["active_response"],
            "full_log": "2026/11/07 10:00:01 active-response/bin/firewall-drop: "
            '{"command":"delete","parameters":{"alert":{"id":"origin-9","rule":'
            '{"id":"31101","level":5,"description":"Web server 400 error code.",'
            '"groups":["web","accesslog","attack"]},"data":{"srcip":"192.0.2.44"}}}}',
        }
        origin = extract_active_response(alert)
        self.assertTrue(origin["is_active_response"])
        self.assertEqual(origin["origin"]["alert_id"], "origin-9")
        self.assertEqual(origin["origin"]["rule_id"], "31101")
        self.assertEqual(origin["origin"]["source_ip"], "192.0.2.44")

    def test_non_active_response_does_not_invent_an_origin(self):
        origin = extract_active_response({
            "rule_id": "5710",
            "rule_level": 5,
            "rule_groups": ["sshd"],
            "full_log": "Nov  7 10:00:00 host-a sshd[1]: Invalid user nobody from 192.0.2.10",
        })
        self.assertFalse(origin["is_active_response"])
        self.assertIsNone(origin["origin"])


class ClassificationTests(unittest.TestCase):
    def test_active_response_is_a_linked_response_not_a_primary_attack(self):
        intel = classify_alert(_active_response())
        self.assertEqual(intel["verdict"], "fp")
        self.assertEqual(intel["role"], "response")
        self.assertEqual(intel["origin_verdict"], "tp")
        self.assertEqual(intel["origin"]["rule_id"], "5710")
        self.assertIn("origin_link", {signal["code"] for signal in intel["signals"]})

    def test_curated_rule_priors_are_explicit_and_auditable(self):
        intel = classify_alert({
            "rule_id": "5710",
            "rule_level": 5,
            "description": "sshd: Attempt to login using a non-existent user",
            "rule_groups": ["sysadmin", "sshd", "invalid_login"],
        })
        self.assertEqual(intel["verdict"], "tp")
        self.assertEqual(intel["role"], "indicator")
        self.assertEqual(intel["source"], "curated_rule")
        self.assertGreaterEqual(intel["confidence"], 0.9)
        self.assertIn("rule_profile", {signal["code"] for signal in intel["signals"]})

    def test_vulnerability_solved_is_context_not_an_attack(self):
        intel = classify_alert({
            "rule_id": "23502",
            "rule_level": 3,
            "description": "The CVE-2026-0001 was solved due to an update in the agent or feed.",
            "rule_groups": ["vulnerability-detector"],
        })
        self.assertEqual(intel["verdict"], "fp")
        self.assertEqual(intel["role"], "context")

    def test_unknown_high_severity_stays_needs_review(self):
        intel = classify_alert({
            "rule_id": "999999",
            "rule_level": 14,
            "description": "Unmapped custom event",
            "rule_groups": [],
        })
        self.assertEqual(intel["verdict"], "needs_review")
        self.assertEqual(intel["priority"], "critical")
        self.assertNotIn("aman", intel["reason"].lower())
        self.assertNotIn("clean", intel["reason"].lower())

    def test_known_bad_source_raises_priority_without_inventing_a_verdict(self):
        intel = classify_alert(
            {"rule_id": "999999", "rule_level": 3, "description": "Unmapped", "rule_groups": []},
            intel={"abuse_score": 95},
        )
        self.assertEqual(intel["verdict"], "needs_review")
        self.assertTrue(intel["known_bad_source"])
        self.assertEqual(intel["priority"], "medium")
        self.assertIn("known_bad_source", {signal["code"] for signal in intel["signals"]})


class CorrelationTests(unittest.TestCase):
    def _primary(self, alert_id: str, rule_id: str, source_ip: str, level: int = 5) -> dict:
        return {
            "id": alert_id,
            "alert_id": alert_id,
            "timestamp": "2026-11-07T10:00:00Z",
            "agent_name": "host-a",
            "rule_id": rule_id,
            "rule_level": level,
            "description": "sshd: Attempt to login using a non-existent user" if rule_id == "5710" else "Web server 400 error code.",
            "rule_groups": ["sshd", "authentication_failed"] if rule_id == "5710" else ["web", "accesslog", "attack"],
            "source_ip": source_ip,
            "hit_count": 1,
        }

    def test_response_is_attached_to_its_origin_group(self):
        primary = self._primary("origin-1", "5710", "192.0.2.10")
        groups = correlate_alerts([primary, _active_response()])
        self.assertEqual(len(groups), 1)
        group = groups[0]
        self.assertEqual(set(group["primary_alert_ids"]), {"origin-1"})
        self.assertEqual(set(group["response_alert_ids"]), {"response-1"})
        self.assertEqual(group["alert_count"], 2)
        self.assertEqual(group["verdict"], "tp")
        self.assertTrue(group["chain"])

    def test_response_without_origin_is_kept_as_standalone_evidence(self):
        groups = correlate_alerts([_active_response(origin_id="outside-scope")])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["alert_ids"], ["response-1"])
        self.assertEqual(groups[0]["response_alert_count"], 0)
        self.assertEqual(groups[0]["verdict"], "fp")

    def test_rotating_source_ips_still_collapse_into_one_host_rule_group(self):
        alerts = [
            self._primary("a1", "5710", "192.0.2.10"),
            self._primary("a2", "5710", "192.0.2.11"),
            self._primary("a3", "5710", "192.0.2.12"),
        ]
        groups = correlate_alerts(alerts)
        self.assertEqual(len(groups), 1)
        self.assertEqual(set(groups[0]["source_ips"]), {"192.0.2.10", "192.0.2.11", "192.0.2.12"})

    def test_attack_chain_orders_multi_rule_stages(self):
        alerts = [
            self._primary("a1", "5710", "192.0.2.10"),
            {
                **self._primary("a2", "5402", "192.0.2.10", level=3),
                "description": "Successful sudo to ROOT executed.",
                "rule_groups": ["syslog", "sudo"],
                "timestamp": "2026-11-07T10:05:00Z",
            },
            {
                **self._primary("a3", "2833", "192.0.2.10", level=8),
                "description": "Root's crontab entry changed.",
                "rule_groups": ["syslog", "cron"],
                "timestamp": "2026-11-07T10:10:00Z",
            },
        ]
        chains = build_attack_chains(alerts)
        self.assertEqual(len(chains), 1)
        stages = [step["stage"] for step in chains[0]["stages"]]
        self.assertEqual(stages, ["credential_access", "expected_admin", "persistence"])


class NormalizeIntegrationTests(unittest.TestCase):
    def test_normalize_alert_persists_classification_metadata(self):
        raw = {
            "id": "wazuh-651",
            "timestamp": "2026-11-07T10:00:01Z",
            "agent": {"name": "host-a", "labels": {"tenant": "Alpha"}},
            "rule": {
                "id": "651",
                "level": 3,
                "description": "Host Blocked by firewall-drop Active Response",
                "groups": ["ossec", "active_response"],
            },
            "data": _active_response()["data"],
            "full_log": _active_response()["full_log"],
        }
        alert = normalize_alert(raw)
        intel = alert["parsed_details"]["wazuh_intel"]
        self.assertEqual(intel["role"], "response")
        self.assertEqual(intel["verdict"], "fp")
        self.assertEqual(intel["origin"]["rule_id"], "5710")
        # Existing normalized fields remain intact.
        self.assertEqual(alert["tenant"], "Alpha")
        self.assertEqual(alert["rule_id"], "651")

    def test_apache_cgi_traversal_and_leakix_scanner_classified_as_tp(self):
        traversal_log = (
            '198.51.100.77 - - [08/Nov/2026:10:15:00 +0700] '
            '"GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/hosts HTTP/1.1" '
            '400 487 "-" "Lkx-Apache2449TraversalPlugin/0.0.1 (+https://leakix.net/, +https://twitter.com/HaboubiAnis)"'
        )
        raw = {
            "id": "wazuh-31101",
            "timestamp": "2026-11-08T03:15:00Z",
            "agent": {"name": "web-prod-01", "labels": {"tenant": "Alpha"}},
            "rule": {
                "id": "31101",
                "level": 5,
                "description": "Web server 400 error code.",
                "groups": ["web", "accesslog"],
            },
            "data": {"srcip": "198.51.100.77"},
            "full_log": traversal_log,
        }
        alert = normalize_alert(raw)
        intel = alert["parsed_details"]["wazuh_intel"]
        self.assertEqual(intel["verdict"], "tp")
        self.assertEqual(intel["role"], "indicator")
        self.assertEqual(intel["source"], "payload_indicator")
        self.assertIn("Path Traversal", intel["reason"])


if __name__ == "__main__":
    unittest.main()
