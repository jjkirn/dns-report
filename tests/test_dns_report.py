"""Tests run against synthetic fixtures - no live Elasticsearch or ipinfo.io
network access required. Run with: python3 -m pytest tests/ -v
(or plain: python3 tests/test_dns_report.py)
"""

import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import es_client
import ip_enrich
import dns_report

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")

LOCAL_SUBNET = "192.168.1.0/24"
AUTHORIZED = ["192.168.1.248", "192.168.1.249"]


def load_fixture(name):
    with open(os.path.join(FIXTURES, name)) as f:
        return json.load(f)


class TestQueryBuilders(unittest.TestCase):
    """Make sure the exclusion logic is actually in the queries we build."""

    def test_bypass_query_excludes_authorized_servers_both_directions(self):
        fake_es = MagicMock()
        es_client.query_bypass_dns_usage(
            fake_es, LOCAL_SUBNET, AUTHORIZED, 24, 500, 200
        )
        body = fake_es.search.call_args[0][0]
        must_not = body["query"]["bool"]["must_not"]
        excluded_fields = {list(clause["terms"].keys())[0] for clause in must_not}
        self.assertIn("source.ip", excluded_fields)
        self.assertIn("destination.ip", excluded_fields)
        for clause in must_not:
            field = list(clause["terms"].keys())[0]
            self.assertEqual(clause["terms"][field], AUTHORIZED)

    def test_authorized_query_filters_on_authorized_servers_as_destination(self):
        fake_es = MagicMock()
        es_client.query_authorized_dns_usage(
            fake_es, LOCAL_SUBNET, AUTHORIZED, 24, 500, 200
        )
        body = fake_es.search.call_args[0][0]
        filters = body["query"]["bool"]["filter"]
        dest_filters = [f for f in filters if "terms" in f and "destination.ip" in f["terms"]]
        self.assertEqual(len(dest_filters), 1)
        self.assertEqual(dest_filters[0]["terms"]["destination.ip"], AUTHORIZED)
        # ns1/ns2's own upstream forwarder traffic must not count as a "client"
        must_not = body["query"]["bool"]["must_not"]
        self.assertTrue(any(
            "terms" in m and m["terms"].get("source.ip") == AUTHORIZED for m in must_not
        ))


class TestParsing(unittest.TestCase):
    def test_parse_client_buckets_report_a(self):
        resp = load_fixture("report_a_response.json")
        clients = es_client.parse_client_buckets(resp)
        self.assertEqual(len(clients), 2)
        self.assertEqual(clients[0]["client_ip"], "192.168.1.141")
        self.assertEqual(clients[0]["query_count"], 342)
        self.assertIn("142.251.215.142", clients[0]["resolved_ips"])
        self.assertEqual(clients[0]["servers"], ["192.168.1.248"])

    def test_parse_client_buckets_report_b(self):
        resp = load_fixture("report_b_response.json")
        clients = es_client.parse_client_buckets(resp)
        self.assertEqual(len(clients), 1)
        self.assertEqual(clients[0]["client_ip"], "192.168.1.88")
        self.assertEqual(clients[0]["servers"], ["1.1.1.1"])


class TestIPEnricher(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.cache_path = os.path.join(self.tmpdir, "ip_cache.json")

    def test_private_ips_are_skipped(self):
        enricher = ip_enrich.IPEnricher(self.cache_path)
        for ip in ["192.168.1.5", "10.0.0.1", "127.0.0.1", "not-an-ip"]:
            self.assertIsNone(enricher.lookup(ip))

    @patch("ip_enrich.requests.get")
    def test_public_ip_is_fetched_and_cached(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "org": "AS15169 Google LLC", "city": "Mountain View",
            "region": "California", "country": "US", "hostname": "",
        }
        mock_get.return_value = mock_resp

        enricher = ip_enrich.IPEnricher(self.cache_path)
        info = enricher.lookup("142.251.215.142")
        self.assertEqual(info["org"], "AS15169 Google LLC")
        self.assertEqual(mock_get.call_count, 1)

        # Second lookup of same IP should hit the cache, not call requests.get again.
        info2 = enricher.lookup("142.251.215.142")
        self.assertEqual(info2["org"], "AS15169 Google LLC")
        self.assertEqual(mock_get.call_count, 1)

    @patch("ip_enrich.requests.get")
    def test_cache_persists_to_disk(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"org": "Example Org"}
        mock_get.return_value = mock_resp

        enricher = ip_enrich.IPEnricher(self.cache_path)
        enricher.lookup("8.8.8.8")
        enricher.save()

        self.assertTrue(os.path.exists(self.cache_path))
        enricher2 = ip_enrich.IPEnricher(self.cache_path)
        self.assertIn("8.8.8.8", enricher2.cache)
        # No network call needed this time since it's already cached and fresh.
        info = enricher2.lookup("8.8.8.8")
        self.assertEqual(info["org"], "Example Org")
        self.assertEqual(mock_get.call_count, 1)  # still just the original call


class TestEndToEndRender(unittest.TestCase):
    """Confirms report building + HTML rendering works end-to-end against
    fixtures, including the ns1-forwarding-upstream edge case being excluded.

    Note: "Report A" (which hosts used ns1/ns2) was dropped from dns_report.py
    on 2026-11-10 - it was structurally unreliable because Security Onion's
    Zeek sensor only sees traffic that crosses the switch's SPAN-mirrored
    uplink port, and intra-LAN traffic to ns1/ns2 never does. The report_a
    fixture/query builder are kept around in es_client.py (still unit-tested
    above) in case this is ever revisited via a different data source (e.g.
    BIND9 query logs), but dns_report.py itself now only builds the bypass
    report (formerly "Report B")."""

    @patch("ip_enrich.requests.get")
    def test_full_pipeline_renders_html(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"org": "Test Org", "city": "Testville",
                                        "region": "TS", "country": "US", "hostname": ""}
        mock_get.return_value = mock_resp

        report_b = es_client.parse_client_buckets(load_fixture("report_b_response.json"))

        tmpdir = tempfile.mkdtemp()
        enricher = ip_enrich.IPEnricher(os.path.join(tmpdir, "cache.json"))
        dns_report.enrich_clients(report_b, enricher)

        cfg = {
            "report": {"lookback_hours": 24},
            "dns": {"local_subnet": LOCAL_SUBNET, "authorized_servers": AUTHORIZED},
        }
        html = dns_report.render_html(report_b, cfg)

        self.assertIn("192.168.1.88", html)
        self.assertIn("DNS Bypass Report", html)
        self.assertNotIn("Report A", html)
        # The upstream-forwarder edge case (ns1/ns2 themselves as source) must
        # never appear as a "client" - check at the data level, since ns1/ns2's
        # IPs legitimately appear in the "server used" column and would make a
        # raw HTML substring check unreliable.
        client_ips = {c["client_ip"] for c in report_b}
        self.assertFalse(client_ips & set(AUTHORIZED))


if __name__ == "__main__":
    unittest.main()
