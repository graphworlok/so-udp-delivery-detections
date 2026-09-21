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
    find a detection by publicId+engine with _search. The fields written on
    create were read back from a detection SOC itself created through the UI,
    field for field, rather than inferred.

    That makes this consistent with how SO operates. It is still NOT a
    supported interface.

WHY UPDATES REPLACE RATHER THAN EDIT
    Measured on SO 3.3.0, 2026-09-20: a create and an in-place _update were
    written at 23:59:16. SOC recompiled all-rulesets.rules at 00:10:31, with
    both already in Elasticsearch. The created rule was compiled; the edited
    one was not, and the compiled file kept the old revision. SOC evidently
    keeps its own copy of each detection and refreshes only what it believes
    changed, so an edit made outside SOC goes unnoticed.

    Creates are noticed, unavoidably, because the document is new. So an
    update here is a delete followed by a create under a fresh document id.
    createTime, userId, author, isEnabled and any overrides attached to the
    original are carried across. `--in-place` restores the old behaviour for
    comparison; it is not expected to compile.

    The cost is a brief window where the rule does not exist, and the failure
    mode if the create fails after the delete - in which case the tool prints
    the rule text to paste into the UI.

RISKS, PLAINLY
    - It bypasses the validation SOC runs when you save a rule in the UI.
      Validate with `so-udp-delivery test` first. That is not optional.
    - Replacing changes the document id. Anything holding a reference to the
      old id will not follow.
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


def get_field(source, name):
    """Read so_detection.<name> from a _source that may be flat or nested.

    Elasticsearch accepts dotted keys in a document and expands them into
    nested objects, so _source can come back either as
    {"so_detection.content": ...} or {"so_detection": {"content": ...}}
    depending on how the document was written. Reading only the flat form
    silently returns None for every field, which makes every rule look
    changed and every rev look unknown.
    """
    flat = source.get("so_detection.%s" % name)
    if flat is not None:
        return flat
    nested = source.get("so_detection")
    if isinstance(nested, dict):
        return nested.get(name)
    return None


def source_is_nested(source):
    return isinstance(source.get("so_detection"), dict)


def set_field(doc, name, value, nested):
    """Set so_detection.<name> in whichever shape the document uses."""
    if nested:
        doc.setdefault("so_detection", {})[name] = value
    else:
        doc["so_detection.%s" % name] = value


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
    return get_field(hits[0]["_source"], "userId") if hits else None


def build_doc(rule, author, user_id, now, nested=False):
    """Build the document, mirroring the shape existing detections use."""
    detection = {
        "createTime": now,
        "userId": user_id,
        "publicId": rule["sid"],
        "title": rule["title"],
        "severity": rule["severity"],
        "author": author,
        "description": SOC_DEFAULT_DESCRIPTION,
        "content": rule["content"],
        "isEnabled": True,
        "isReporting": False,
        "isCommunity": False,
        "engine": ENGINE,
        "language": ENGINE,
        "overrides": [],
        "tags": None,
        "ruleset": RULESET,
        "license": SOC_DEFAULT_LICENSE,
        "sourceCreated": rule["sourceCreated"],
        "sourceUpdated": None,
    }
    if nested:
        return {"@timestamp": now, "so_kind": "detection",
                "so_detection": detection}
    doc = {"@timestamp": now, "so_kind": "detection"}
    for key, value in detection.items():
        doc["so_detection.%s" % key] = value
    return doc


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
    ap.add_argument("--in-place", action="store_true",
                    help="update existing detections with _update instead of "
                         "replacing them. Measured not to recompile on SO "
                         "3.3.0; kept for comparison only.")
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
        elif get_field(existing["_source"], "content") != rule["content"]:
            updates.append((rule, existing))
        else:
            unchanged.append((rule, existing))

    # A rule whose text changed but whose rev did not is a mistake, not an
    # update: Suricata and SOC identify versions by rev, so two different
    # texts under one sid+rev are indistinguishable downstream. Refuse them.
    stale = []
    for rule, existing in list(updates):
        old_rev = rev_of(get_field(existing["_source"], "content"))
        if old_rev.isdigit() and rule["rev"] <= int(old_rev):
            stale.append((rule, int(old_rev)))
            updates.remove((rule, existing))

    for rule, _ in creates:
        print("  CREATE  %s  rev:%d  %s" % (rule["sid"], rule["rev"], rule["title"]))
    for rule, existing in updates:
        print("  %s  %s  rev:%s -> %d  %s" % (
            "UPDATE " if args.in_place else "REPLACE",
            rule["sid"], rev_of(get_field(existing["_source"], "content")),
            rule["rev"], rule["title"]))
    for rule, old_rev in stale:
        print("  REFUSED %s  text changed but rev:%d is not above rev:%d"
              % (rule["sid"], rule["rev"], old_rev))
    for rule, _ in unchanged:
        print("  same    %s  rev:%d" % (rule["sid"], rule["rev"]))

    if stale:
        print("\n%d rule(s) refused: their text differs from what SOC holds but"
              % len(stale))
        print("their revision was not bumped. Increment rev: on each and re-run.")

    if not (creates or updates):
        print("\nnothing to do - SOC already holds every rule as written"
              if not stale else "\nnothing else to do.")
        return 1 if stale else 0

    if not args.confirm:
        print("\nDRY RUN - nothing was written. Re-run with --confirm to apply.")
        print("Validate first if you have not:  sudo so-udp-delivery test")
        return 0

    # Write new documents in whatever shape the index already holds, rather
    # than assuming. Any existing detection answers the question.
    nested_shape = False
    probe = (updates or unchanged)
    if probe:
        nested_shape = source_is_nested(probe[0][1]["_source"])

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
                        json=build_doc(rule, args.author, user_id, now,
                                       nested=nested_shape))
        if r.status_code >= 300:
            sys.stderr.write("create %s failed: %s %s\n"
                             % (rule["sid"], r.status_code, r.text[:200]))
            failed += 1
            continue
        print("  created %s as %s" % (rule["sid"], doc_id))
        written += 1

    for rule, existing in updates:
        src = existing["_source"]

        if args.in_place:
            # Kept for comparison only. Measured on SO 3.3.0: the new content
            # lands in the index and SOC never compiles it.
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
            print("  updated %s in place (SOC may not compile this)" % rule["sid"])
            written += 1
            continue

        # Replace: delete the document and write a new one. SOC compiles
        # creates but not in-place edits, so to SOC this has to look like a
        # new detection. Everything worth keeping is carried across first.
        keep_created = get_field(src, "createTime") or now
        keep_user = get_field(src, "userId") or user_id
        keep_author = get_field(src, "author") or args.author
        keep_overrides = get_field(src, "overrides") or []
        keep_enabled = get_field(src, "isEnabled")
        if keep_enabled is None:
            keep_enabled = True

        if keep_overrides:
            print("  carrying %d override(s) across on %s"
                  % (len(keep_overrides), rule["sid"]))

        r = session.delete("%s/%s/_doc/%s?refresh=true"
                           % (ES_URL, existing["_index"], existing["_id"]))
        if r.status_code >= 300:
            sys.stderr.write("delete %s failed, nothing changed: %s %s\n"
                             % (rule["sid"], r.status_code, r.text[:200]))
            failed += 1
            continue

        doc = build_doc(rule, keep_author, keep_user, now, nested=nested_shape)
        set_field(doc, "createTime", keep_created, nested_shape)
        set_field(doc, "overrides", keep_overrides, nested_shape)
        set_field(doc, "isEnabled", keep_enabled, nested_shape)

        doc_id = str(uuid.uuid4())
        r = session.put("%s/%s/_doc/%s?refresh=true" % (ES_URL, INDEX, doc_id),
                        json=doc)
        if r.status_code >= 300:
            # The old document is already gone. Say so loudly and hand back
            # the rule text so it can be pasted into the UI.
            sys.stderr.write(
                "\n*** %s WAS DELETED AND THE REPLACEMENT FAILED ***\n"
                "%s %s\n"
                "Paste this into SOC -> Detections -> New Detection:\n\n%s\n\n"
                % (rule["sid"], r.status_code, r.text[:200], rule["content"]))
            failed += 1
            continue
        print("  replaced %s as %s (was %s)"
              % (rule["sid"], doc_id, existing["_id"]))
        written += 1

    print("\n%d written, %d failed." % (written, failed))

    if updates and args.in_place:
        print("")
        print("WARNING: --in-place updates reach the index but are not compiled.")
        print("Measured on SO 3.3.0: SOC compiled a created rule and ignored an")
        print("edited one eleven minutes later, with the new revision already in")
        print("Elasticsearch. Drop --in-place to replace instead.")
    elif updates:
        print("")
        print("Replaced rules were deleted and rewritten under a new document id,")
        print("so SOC sees them as new. Confirm each one compiled:")
        for rule, _ in updates:
            print("  grep -c 'sid:%s; rev:%d' /opt/so/rules/suricata/all-rulesets.rules"
                  % (rule["sid"], rule["rev"]))

    if creates:
        print("")
        print("Creates compile normally. Verify with:")
        print("  grep -c 'LOCAL IOT-DELIVERY' /opt/so/rules/suricata/all-rulesets.rules")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
