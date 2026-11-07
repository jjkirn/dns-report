# dns-report

Daily DNS usage report for the home LAN, built from Security Onion's Zeek
`dns.log` (pulled via the Elasticsearch REST API). Produces one HTML page
with two sections:

- **Report A** - which LAN hosts used the authorized local DNS servers
  (ns1/ns2), and what internet IPs those lookups resolved to, enriched
  with org/location info from ipinfo.io and a link to look the IP up
  further.
- **Report B** - which LAN hosts queried some *other* DNS server instead
  (bypassing ns1/ns2), same enrichment. ns1/ns2's own upstream forwarder
  lookups are excluded so they don't show up as false "bypass" entries.

Meant to run once a day from cron on `velo`.

## How it works

Security Onion's Zeek sensor sees every DNS packet on the LAN (regardless
of which server answers it), so there's no need to parse BIND9's logs
directly - this queries Security Onion's Elasticsearch instead
(`event.dataset:"zeek.dns"`), which already has the resolved IPs attached
to each query.

## Setup

1. **Install dependencies** (Python 3.8+):

   ```bash
   pip3 install --break-system-packages -r requirements.txt
   ```

2. **Copy the config file and adjust it** if needed (your so1 host/IP,
   ns1/ns2 IPs, output directory, etc. - the defaults already match your
   setup):

   ```bash
   cp config.example.yaml config.yaml
   ```

3. **Set the Elasticsearch API key as an environment variable** - this is
   deliberately kept OUT of config.yaml and the git repo. The simplest way
   is a local `.env` file (already gitignored):

   ```bash
   echo "export DNS_REPORT_ES_API_KEY='<paste the dns-report-readonly API key here>'" > .env
   chmod 600 .env
   source .env
   ```

   For cron, source it inside the cron job itself (see below) rather than
   relying on an interactive shell having it set.

   Optional: if you later get an ipinfo.io token, set
   `DNS_REPORT_IPINFO_TOKEN` the same way. Not required - it works fine on
   the free/anonymous tier for a home LAN's volume.

4. **Test it by hand first:**

   ```bash
   source .env
   python3 dns_report.py
   ```

   This should print something like:
   ```
   Wrote /var/www/html/dns_report/dns_report_2026-11-06.html
   Wrote /var/www/html/dns_report/index.html
   Report A (ns1/ns2 users): 12 client(s)
   Report B (bypass DNS users): 1 client(s)
     -> Bypass clients: 192.168.1.88
   ```

   If `config.yaml`'s `output_dir` isn't writable by your user (e.g. it's
   owned by www-data), either `chmod`/`chown` it, or point `output_dir` at
   somewhere in your home directory and have your web server's docroot
   symlink to it - whichever's easier on velo.

5. **Check the output** by opening `index.html` in a browser (or whatever
   path you configured). It should look like the preview I sent you.

6. **Schedule it daily with cron:**

   ```bash
   crontab -e
   ```

   Add a line like (runs at 6:00 AM, after a full day's traffic has
   accumulated - adjust to taste):

   ```
   0 6 * * * cd /home/jim/dns-report && source .env && /usr/bin/python3 dns_report.py >> run.log 2>&1
   ```

## Files

| File | Purpose |
|---|---|
| `dns_report.py` | Main entry point - run this |
| `config.example.yaml` / `config.yaml` | Settings (ns1/ns2 IPs, subnet, output path, etc.) |
| `config.py` | Loads config.yaml + required env vars |
| `es_client.py` | Builds/runs the two Elasticsearch queries |
| `ip_enrich.py` | ipinfo.io lookups with an on-disk cache (`ip_cache.json`) |
| `templates/report.html.j2` | The HTML report layout |
| `tests/` | Unit tests against synthetic fixtures (no live network needed) |

## Running the tests

```bash
pip3 install --break-system-packages pytest
python3 -m pytest tests/ -v
```

These run entirely against fixture data in `tests/fixtures/` - they don't
touch your real Elasticsearch or ipinfo.io, so they're safe to run
anywhere, including before you've even set up `config.yaml`.

## Notes / things to double check once it's live

- **Field mapping assumption**: `dns.resolved_ip` is used as the
  aggregatable field for resolved answer IPs. If the very first real run
  errors out on that field (e.g. "Fielddata is disabled on text fields"),
  it means Security Onion's mapping for that field differs slightly from
  what the sample doc we inspected showed - in that case try
  `dns.answers.name` instead in `es_client.py`'s `_client_agg()`
  (`resolved_ips` aggregation), or ping me and I'll adjust it.
- **Lookback window**: defaults to the last 24 hours at the moment the
  script runs (not "yesterday's calendar day"). If you'd rather have it
  always cover exactly the previous calendar day, say so and I'll adjust
  the query's time range.
- **API key scope**: the `dns-report-readonly` key was created with
  default/unrestricted privileges to get this working quickly. Worth
  tightening later to read-only access scoped to just the `logs-zeek-so*`
  index pattern, in Kibana's API key settings.
- **History/trends**: right now each day's report only covers that day's
  window - nothing is retained across days. If you want a running history
  (new bypass hosts, usage trends over time, similar to the Autoruns/
  Scanlan delta reports), that's a natural next step, just say the word.
