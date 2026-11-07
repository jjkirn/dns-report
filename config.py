"""Config loading for the DNS report tool.

Settings live in config.yaml (copy config.example.yaml to get started).
The Elasticsearch API key is deliberately NOT part of config.yaml - it's
read from the DNS_REPORT_ES_API_KEY environment variable so it never ends
up committed to git. Same deal for an optional ipinfo.io token
(DNS_REPORT_IPINFO_TOKEN), though that one works fine unset too.
"""

import os
import sys
import yaml

DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.yaml")


class ConfigError(RuntimeError):
    pass


def load_config(path=None):
    path = path or DEFAULT_CONFIG_PATH
    if not os.path.exists(path):
        raise ConfigError(
            f"Config file not found: {path}\n"
            f"Copy config.example.yaml to config.yaml and edit it first."
        )
    with open(path, "r") as f:
        cfg = yaml.safe_load(f) or {}

    cfg["_es_api_key"] = os.environ.get("DNS_REPORT_ES_API_KEY", "").strip()
    if not cfg["_es_api_key"]:
        raise ConfigError(
            "DNS_REPORT_ES_API_KEY environment variable is not set.\n"
            "Set it to the Elasticsearch API key (the base64 'Encoded' value "
            "from Kibana -> Stack Management -> API Keys), e.g.:\n"
            "  export DNS_REPORT_ES_API_KEY='...'\n"
            "or put that line in a local .env file and source it - just don't "
            "commit it."
        )

    cfg["_ipinfo_token"] = os.environ.get("DNS_REPORT_IPINFO_TOKEN", "").strip()

    return cfg


def die(msg):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)
