#!/usr/bin/env python3
"""Evaluate embedded-IPv4 rule candidates against captured UDP payloads.

Read-only. Pulls every alerted UDP payload to the WAN address from the last
N days (only alerts carry network.data.decoded) and reports, per candidate
pattern, how many payloads it matches and on which destination ports - so a
candidate can be judged against real noise before it becomes a rule.

Run on the manager:  sudo python3 tools/ip-rule-eval.py [days]
"""

import collections
import ipaddress
import re
import sys

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AUTH_FILE = "/opt/so/conf/elasticsearch/curl.config"
ES = "https://localhost:9200"
WAN = "14.203.163.145"
DAYS = int(sys.argv[1]) if len(sys.argv) > 1 else 7

# Known delivery ports, used only to label results as delivery vs noise.
DELIVERY_PORTS = {9034, 9999, 43561, 43562, 500}

IPV4 = r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(?![\d.])"


def session():
    for line in open(AUTH_FILE):
        if line.startswith("user ="):
            u, _, p = line.split("=", 1)[1].strip().replace('"', "").partition(":")
            s = requests.Session()
            s.auth = HTTPBasicAuth(u, p)
            s.verify = False
            return s
    raise SystemExit("no creds")


def is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast and ip != WAN


def ips_where(payload, suffix):
    """Public IPv4s in payload that are immediately followed by `suffix`."""
    out = []
    for m in re.finditer(IPV4 + suffix, payload):
        if is_public(m.group(1)):
            out.append(m.group(1))
    return out


CANDIDATES = {
    "A any IPv4": lambda p: bool(re.search(IPV4, p)),
    "B any public IPv4": lambda p: any(is_public(m.group(1))
                                       for m in re.finditer(IPV4, p)),
    "C public IP then /path": lambda p: bool(ips_where(p, r"(?::\d{1,5})?/[^\s/]")),
    "D public IP then space+port": lambda p: bool(ips_where(p, r"\s+\d{2,5}\b")),
    "E C or D": lambda p: bool(ips_where(p, r"(?::\d{1,5})?/[^\s/]")
                               or ips_where(p, r"\s+\d{2,5}\b")),
}


def main():
    s = session()
    body = {
        "size": 5000,
        "_source": ["network.data.decoded", "destination.port"],
        "query": {"bool": {"filter": [
            {"range": {"@timestamp": {"gte": "now-%dd" % DAYS}}},
            {"term": {"destination.ip": WAN}},
            {"term": {"network.transport": "udp"}},
            {"exists": {"field": "network.data.decoded"}},
        ]}},
    }
    r = s.post(ES + "/logs-suricata.alerts-so/_search", json=body)
    r.raise_for_status()
    hits = r.json()["hits"]["hits"]

    # One row per distinct (port, payload): several rules fire per datagram.
    rows = {}
    for h in hits:
        src = h["_source"]
        payload = (src.get("network", {}).get("data", {}).get("decoded")
                   or src.get("network.data.decoded") or "")
        port = (src.get("destination", {}).get("port")
                or src.get("destination.port"))
        rows[(port, payload)] = True
    print("distinct UDP payloads to WAN, last %d days: %d\n" % (DAYS, len(rows)))

    for name, pred in CANDIDATES.items():
        deliver, noise = 0, collections.Counter()
        for (port, payload) in rows:
            if pred(payload):
                if port in DELIVERY_PORTS:
                    deliver += 1
                else:
                    noise[port] += 1
        total_noise = sum(noise.values())
        top = ", ".join("%s:%d" % kv for kv in noise.most_common(6)) or "-"
        print("%-28s delivery-port %4d | other %4d  [%s]"
              % (name, deliver, total_noise, top))


if __name__ == "__main__":
    main()
