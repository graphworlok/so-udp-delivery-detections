#!/usr/bin/env python3
"""Create or update custom Suricata detections in the so-detection index.

WHY THIS EXISTS
    On Security Onion 2.4+ Suricata loads a single rules file that SOC
    compiles from the so-detection index, so that index is the only way in.
    SOC's web UI is the supported path. Nothing shipped with SO *creates* a
    detection from the command line - so-detections-overrides-import handles
    overrides only.

WHY IT IS SHAPED THIS WAY
    It deliberately copies what Security Onion's own
    /usr/sbin/so-detections-overrides-import does: read basic-auth creds from
    /opt/so/conf/elasticsearch/curl.config, talk to https://localhost:9200,
    find a detection by publicId+engine with _search, change it with _update.
    The fields written on create were read back from a detection SOC itself
    created through the UI, field for field, rather than inferred.

    That makes this consistent with how SO operates. It is still NOT a
    supported interface.

RISKS, PLAINLY
    - It bypasses the validation SOC runs when you save a rule in the UI.
      Validate with `so-udp-delivery test` first. That is not optional.
    - SOC's caching behaviour for externally inserted documents is not
      something this repo has tested. The overrides tool implies SOC re-reads
      the index, but that is inference for *creation*.
    - The schema belongs to SOC and can change on upgrade.

    Use the UI for a first install. This earns its keep on rev bumps and
    rebuilds, where clicking through N rules does not scale.

Usage:
    sudo python3 tools/push-soc.py <rules-file> [--sid N] [--confirm]
"""

import argparse
import os
import re
import sys
import uuid
from datetime import datetime, timezone

try:
    import requests
    from requests.auth import HTTPBasicAuth
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    sys.stderr.write("needs python3 requests, which Security Onion ships\n")
    sys.exit(2)

AUTH_FILE = "/opt/so/conf/elasticsearch/curl.config"
ES_URL = "https://localhost:9200"
INDEX = "so-detection"
RULESET = "__custom__"
ENGINE = "suricata"

# SOC's own defaults, read back from a detection it created through the UI.
SOC_DEFAULT_DESCRIPTION = "Detection description not yet provided"
SOC_DEFAULT_LICENSE = "AGPL-3.0-only"


def make_session(auth_file):
    """Identical parsing to so-detections-overrides-import."""
    with open(auth_file, "r") as fh:
        for line in fh:
            if line.startswith("user ="):
                creds = line.split("=", 1)[1].strip().replace('"', "")
                user, _, password = creds.partition(":")
                session = requests.Session()
                session.auth = HTTPBasicAuth(user, password)
                session.headers.update({"Content-Type": "application/json"})
                session.verify = False
                return session
    raise RuntimeError("no 'user =' line in %s" % auth_file)


def parse_rules(path):
    """Yield a dict per alert rule in a .rules file."""
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("alert "):
                continue
            sid = re.search(r"\bsid:(\d+)\s*;", line)
            msg = re.search(r'\bmsg:"([^"]+)"', line)
            rev = re.search(r"\brev:(\d+)\s*;", line)
            if not (sid and msg):
                sys.stderr.write("skipping rule with no sid/msg: %.60s\n" % line)
                continue
            created = re.search(r"created_at (\d{4})_(\d{2})_(\d{2})", line)
            out.append({
                "sid": sid.group(1),
                "title": msg.group(1),
                "rev": int(rev.group(1)) if rev else 1,
                "content": line,
                # SOC derived severity from the metadata signature_severity.
                "severity": ("critical" if "signature_severity Critical" in line
                             else "high"),
                "sourceCreated": ("%s-%s-%sT00:00:00Z" % created.groups()
                                  if created else None),
            })
    return out


def find_detection(session, public_id):
    query = {
        "query": {"bool": {"filter": [
            {"term": {"so_detection.publicId": public_id}},
            {"term": {"so_detection.engine": ENGINE}},
        ]}},
        "size": 1,
    }
    r = session.get("%s/%s/_search" % (ES_URL, INDEX), json=query)
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    return hits[0] if hits else None


def borrow_user_id(session):
    """Reuse the userId from an existing custom detection.

    SOC stamps the Kratos user id of whoever created the detection. Copying it
    keeps ownership consistent and avoids resolving a Kratos identity here.
    """
    query = {
        "query": {"bool": {"filter": [
            {"term": {"so_detection.ruleset": RULESET}},
        ]}},
        "size": 1,
    }
    r = session.get("%s/%s/_search" % (ES_URL, INDEX), json=query)
    r.raise_for_status()
    hits = r.json().get("hits", {}).get("hits", [])
    return hits[0]["_source"].get("so_detection.userId") if hits else None


def build_doc(rule, author, user_id, now):
    return {
        "@timestamp": now,
        "so_detection.createTime": now,
        "so_detection.userId": user_id,
        "so_detection.publicId": rule["sid"],
        "so_detection.title": rule["title"],
        "so_detection.severity": rule["severity"],
        "so_detection.author": author,
        "so_detection.description": SOC_DEFAULT_DESCRIPTION,
        "so_detection.content": rule["content"],
        "so_detection.isEnabled": True,
        "so_detection.isReporting": False,
        "so_detection.isCommunity": False,
        "so_detection.engine": ENGINE,
        "so_detection.language": ENGINE,
        "so_detection.overrides": [],
        "so_detection.tags": None,
        "so_detection.ruleset": RULESET,
        "so_detection.license": SOC_DEFAULT_LICENSE,
        "so_detection.sourceCreated": rule["sourceCreated"],
        "so_detection.sourceUpdated": None,
        "so_kind": "detection",
    }


def rev_of(content):
    m = re.search(r"\brev:(\d+)\s*;", content or "")
    return m.group(1) if m else "?"


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("rules", help="path to the .rules file")
    ap.add_argument("--sid", action="append",
                    help="only push this SID; repeat for several")
    ap.add_argument("--confirm", action="store_true",
                    help="actually write. Without it nothing is sent.")
    ap.add_argument("--author", default=os.environ.get("SUDO_USER") or "unknown")
    ap.add_argument("--auth-file", default=AUTH_FILE)
    args = ap.parse_args()

    rules = parse_rules(args.rules)
    if args.sid:
        wanted = set(args.sid)
        rules = [r for r in rules if r["sid"] in wanted]
    if not rules:
        sys.stderr.write("no matching rules in %s\n" % args.rules)
        return 1

    if not os.access(args.auth_file, os.R_OK):
        sys.stderr.write("cannot read %s - run under sudo\n" % args.auth_file)
        return 2

    session = make_session(args.auth_file)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f000Z")

    creates, updates, unchanged = [], [], []
    for rule in rules:
        existing = find_detection(session, rule["sid"])
        if existing is None:
            creates.append((rule, None))
        elif existing["_source"].get("so_detection.content") != rule["content"]:
            updates.append((rule, existing))
        else:
            unchanged.append((rule, existing))

    for rule, _ in creates:
        print("  CREATE  %s  rev:%d  %s" % (rule["sid"], rule["rev"], rule["title"]))
    for rule, existing in updates:
        print("  UPDATE  %s  rev:%s -> %d  %s" % (
            rule["sid"], rev_of(existing["_source"].get("so_detection.content")),
            rule["rev"], rule["title"]))
    for rule, _ in unchanged:
        print("  same    %s  rev:%d" % (rule["sid"], rule["rev"]))

    if not (creates or updates):
        print("\nnothing to do - SOC already holds every rule as written")
        return 0

    if not args.confirm:
        print("\nDRY RUN - nothing was written. Re-run with --confirm to apply.")
        print("Validate first if you have not:  sudo so-udp-delivery test")
        return 0

    user_id = borrow_user_id(session)
    if creates and user_id is None:
        sys.stderr.write(
            "no existing custom detection to copy a userId from.\n"
            "Create one rule through the SOC UI first, then re-run.\n")
        return 2

    written = failed = 0
    for rule, _ in creates:
        doc_id = str(uuid.uuid4())
        r = session.put("%s/%s/_doc/%s?refresh=true" % (ES_URL, INDEX, doc_id),
                        json=build_doc(rule, args.author, user_id, now))
        if r.status_code >= 300:
            sys.stderr.write("create %s failed: %s %s\n"
                             % (rule["sid"], r.status_code, r.text[:200]))
            failed += 1
            continue
        print("  created %s as %s" % (rule["sid"], doc_id))
        written += 1

    for rule, existing in updates:
        body = {"doc": {
            "so_detection.content": rule["content"],
            "so_detection.title": rule["title"],
            "so_detection.severity": rule["severity"],
            "@timestamp": now,
        }}
        r = session.post("%s/%s/_update/%s?refresh=true"
                         % (ES_URL, existing["_index"], existing["_id"]),
                         json=body)
        if r.status_code >= 300:
            sys.stderr.write("update %s failed: %s %s\n"
                             % (rule["sid"], r.status_code, r.text[:200]))
            failed += 1
            continue
        print("  updated %s" % rule["sid"])
        written += 1

    print("\n%d written, %d failed." % (written, failed))
    print("SOC recompiles all-rulesets.rules on its own schedule. Verify with:")
    print("  so-udp-delivery verify")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
