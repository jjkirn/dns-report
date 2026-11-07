"""Thin Elasticsearch client for pulling Zeek dns.log data from Security Onion."""

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class ESClient:
    def __init__(self, host, index_pattern, api_key, verify_tls=False, timeout=30):
        self.host = host.rstrip("/")
        self.index_pattern = index_pattern
        self.headers = {
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/json",
        }
        self.verify_tls = verify_tls
        self.timeout = timeout

    def search(self, body):
        url = f"{self.host}/{self.index_pattern}/_search"
        resp = requests.post(
            url, json=body, headers=self.headers,
            verify=self.verify_tls, timeout=self.timeout,
        )
        if resp.status_code != 200:
            raise RuntimeError(
                f"Elasticsearch query failed ({resp.status_code}): {resp.text[:500]}"
            )
        return resp.json()


def _base_filters(lookback_hours):
    return [
        {"term": {"event.dataset": "zeek.dns"}},
        {"term": {"destination.port": 53}},
        {"range": {"@timestamp": {"gte": f"now-{lookback_hours}h", "lte": "now"}}},
    ]


def _client_agg(max_clients, max_resolved_ips):
    return {
        "by_client": {
            "terms": {"field": "source.ip", "size": max_clients},
            "aggs": {
                "by_server": {"terms": {"field": "destination.ip", "size": 5}},
                "resolved_ips": {
                    "terms": {"field": "dns.resolved_ip", "size": max_resolved_ips}
                },
                "query_names": {
                    "terms": {"field": "dns.query.name", "size": 10}
                },
                "last_seen": {"max": {"field": "@timestamp"}},
            },
        }
    }


def query_authorized_dns_usage(es, local_subnet, authorized_servers, lookback_hours,
                                max_clients, max_resolved_ips):
    """Report A: LAN clients that queried ns1/ns2, and what they resolved."""
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": _base_filters(lookback_hours) + [
                    {"term": {"source.ip": local_subnet}},
                    {"terms": {"destination.ip": authorized_servers}},
                ],
                "must_not": [
                    # Don't count ns1/ns2 talking to each other (zone transfers etc.)
                    # as if they were ordinary LAN clients.
                    {"terms": {"source.ip": authorized_servers}},
                ],
            }
        },
        "aggs": _client_agg(max_clients, max_resolved_ips),
    }
    return es.search(body)


def query_bypass_dns_usage(es, local_subnet, authorized_servers, lookback_hours,
                            max_clients, max_resolved_ips):
    """Report B: LAN clients that queried a DNS server OTHER than ns1/ns2.

    Explicitly excludes ns1/ns2 themselves as a source, so their own upstream
    forwarder lookups don't get misreported as a LAN host bypassing local DNS.
    """
    body = {
        "size": 0,
        "query": {
            "bool": {
                "filter": _base_filters(lookback_hours) + [
                    {"term": {"source.ip": local_subnet}},
                ],
                "must_not": [
                    {"terms": {"source.ip": authorized_servers}},
                    {"terms": {"destination.ip": authorized_servers}},
                ],
            }
        },
        "aggs": _client_agg(max_clients, max_resolved_ips),
    }
    return es.search(body)


def parse_client_buckets(es_response):
    """Flatten the by_client aggregation into a list of simple dicts."""
    buckets = es_response.get("aggregations", {}).get("by_client", {}).get("buckets", [])
    out = []
    for b in buckets:
        out.append({
            "client_ip": b["key"],
            "query_count": b["doc_count"],
            "servers": [s["key"] for s in b["by_server"]["buckets"]],
            "resolved_ips": [r["key"] for r in b["resolved_ips"]["buckets"]],
            "query_names": [q["key"] for q in b["query_names"]["buckets"]],
            "last_seen": b["last_seen"].get("value_as_string"),
        })
    return out
