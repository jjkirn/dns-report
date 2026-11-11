#!/usr/bin/env python3
"""Daily DNS bypass report for the home LAN, built from Security Onion's
Zeek dns.log (via Elasticsearch).

Reports which LAN hosts queried a DNS server OTHER than the authorized
local servers (ns1/ns2), and what internet IPs those queries resolved to
(enriched via ipinfo.io).

Note: this report used to also include a "Report A" section (which hosts
DID use ns1/ns2) - that section was dropped on 2026-11-10. It turned out
to be structurally unreliable: Security Onion's Zeek sensor only sees
traffic that crosses the switch's SPAN-mirrored uplink port, and a LAN
client talking to ns1/ns2 (also on the local LAN) never needs to cross
that port, so it was invisible to Zeek regardless of actual usage. Fixing
it would require either reconfiguring the switch's SPAN session or reading
BIND9's own query logs directly - neither was judged worth it, since the
real threat-detection value (catching connections/resolutions touching a
known-bad IP/domain) is already covered by the separate so-intel-feed/
intel-report project, which works regardless of which DNS server was used.

Usage:
    python3 dns_report.py [--config config.yaml] [--out-name dns_report.html]

Intended to run once a day from cron. See README.md for setup.
"""

import argparse
import datetime
import os
import sys

from jinja2 import Environment, FileSystemLoader

from config import load_config, ConfigError, die
from es_client import ESClient, query_bypass_dns_usage, parse_client_buckets
from ip_enrich import IPEnricher

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def enrich_clients(clients, enricher):
    for c in clients:
        enriched = []
        for ip in c["resolved_ips"]:
            info = enricher.lookup(ip)
            if info:
                enriched.append(info)
        c["enriched"] = enriched
    return clients


def build_report(cfg):
    es = ESClient(
        host=cfg["elasticsearch"]["host"],
        index_pattern=cfg["elasticsearch"]["index_pattern"],
        api_key=cfg["_es_api_key"],
        verify_tls=cfg["elasticsearch"].get("verify_tls", False),
        timeout=cfg["elasticsearch"].get("request_timeout_sec", 30),
    )

    local_subnet = cfg["dns"]["local_subnet"]
    authorized = cfg["dns"]["authorized_servers"]
    lookback_hours = cfg["report"]["lookback_hours"]
    max_clients = cfg["report"]["max_clients"]
    max_ips = cfg["report"]["max_resolved_ips_per_client"]

    resp_b = query_bypass_dns_usage(
        es, local_subnet, authorized, lookback_hours, max_clients, max_ips
    )

    report_b = parse_client_buckets(resp_b)

    # Sort busiest clients first - most useful at a glance.
    report_b.sort(key=lambda c: c["query_count"], reverse=True)

    enricher = IPEnricher(
        cache_path=os.path.join(SCRIPT_DIR, cfg["ip_enrichment"]["cache_file"]),
        token=cfg["_ipinfo_token"],
        ttl_days=cfg["ip_enrichment"].get("cache_ttl_days", 30),
    )
    enrich_clients(report_b, enricher)
    enricher.save()

    return report_b


def render_html(report_b, cfg):
    env = Environment(loader=FileSystemLoader(os.path.join(SCRIPT_DIR, "templates")))
    tpl = env.get_template("report.html.j2")
    now = datetime.datetime.now()
    return tpl.render(
        report_date=now.strftime("%Y-%m-%d"),
        generated_at=now.strftime("%Y-%m-%d %H:%M:%S"),
        lookback_hours=cfg["report"]["lookback_hours"],
        local_subnet=cfg["dns"]["local_subnet"],
        authorized_servers=cfg["dns"]["authorized_servers"],
        report_b=report_b,
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=None, help="Path to config.yaml")
    parser.add_argument("--out-name", default=None,
                         help="Override output filename (default: dns_report_YYYY-MM-DD.html)")
    args = parser.parse_args()

    try:
        cfg = load_config(args.config)
    except ConfigError as e:
        die(str(e))

    try:
        report_b = build_report(cfg)
    except Exception as e:
        die(f"Failed to build report: {e}")

    html = render_html(report_b, cfg)

    out_dir = cfg["report"]["output_dir"]
    os.makedirs(out_dir, exist_ok=True)

    today = datetime.date.today().isoformat()
    out_name = args.out_name or f"dns_report_{today}.html"
    out_path = os.path.join(out_dir, out_name)
    with open(out_path, "w") as f:
        f.write(html)

    # Also write/refresh an "index.html" so there's always a stable latest-report URL.
    latest_path = os.path.join(out_dir, "index.html")
    with open(latest_path, "w") as f:
        f.write(html)

    print(f"Wrote {out_path}")
    print(f"Wrote {latest_path}")
    print(f"Bypass DNS users: {len(report_b)} client(s)")
    if report_b:
        print("  -> Bypass clients:", ", ".join(c["client_ip"] for c in report_b))


if __name__ == "__main__":
    main()
