#!/usr/bin/env python3
"""Measure rule coverage against the corpus of real observed payloads.

This re-implements the payload-matching logic of the content rules in
rules/suricata/udp-delivery.rules so coverage can be measured without a
Suricata instance. It is an approximation and deliberately so: its job is to
answer "which real deliveries would nothing catch?", which is a question you
want answered while editing rules, not only at deploy time.

Authoritative validation is still `so-udp-delivery test <pcap>` on the grid.
When the two disagree, Suricata is right and this file has a bug.

Header-only rules (1000010, 1000011's kit half) are not modelled - they match
on IP/UDP header fields, not payload, so a text corpus cannot exercise them.

Usage:  python3 tests/coverage.py [--verbose]
Exit:   non-zero if any corpus payload is matched by no rule at all.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORPUS = os.path.join(HERE, "corpus.tsv")


def content_within(hay, first, second, within, nocase=True):
    """Suricata 'content:A; content:B; distance:0; within:N'.

    B must begin no more than N bytes after the end of an A match. Any A
    match will do, so scan them all.
    """
    h = hay.lower() if nocase else hay
    a = first.lower() if nocase else first
    b = second.lower() if nocase else second
    start = 0
    while True:
        i = h.find(a, start)
        if i < 0:
            return False
        end = i + len(a)
        if 0 <= h.find(b, end) - end <= within and h.find(b, end) >= 0:
            return True
        start = i + 1


# Each entry: sid -> (title, ports or None for any, predicate)
# ports None  = rule is not port-scoped
# ports (a,b) = inclusive range; a corpus line with port 0 is never credited
RULES = [
    (1000001, "Downloader Payload (wget)", None,
     lambda p: content_within(p, "wget", "http", 64)),

    (1000002, "Downloader Payload (tftp)", None,
     lambda p: "tftp" in p.lower() and bool(
         re.search(r"\btftp\b[^\r\n]{0,48}(-[gilr]\b|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                   p, re.I))),

    (1000003, "Downloader Payload (curl)", None,
     lambda p: content_within(p, "curl", "http", 64)),

    (1000004, "Downloader Payload (busybox applet)", None,
     lambda p: "busybox" in p.lower() and bool(
         re.search(r"busybox\s+(wget|tftp|ftpget|nc)\b", p, re.I))),

    (1000005, "Sets Executable Bit", None,
     lambda p: "chmod" in p.lower() and bool(
         re.search(r"chmod\s+(\+x|[0-7]{3,4})\s", p, re.I))),

    (1000008, "Netcat Fetch", None,
     lambda p: "|nc" in p.lower() and bool(
         re.search(r"\|\s*nc\s+(-\w+\s+)*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d{2,5}\b",
                   p, re.I))),

    (1000006, "Fetch Piped To Shell", None,
     lambda p: content_within(p, "http", "|sh", 256)),

    (1000007, "Empty Command Substitution Evasion", None,
     lambda p: "``" in p and "http" in p.lower()),

    (1000021, "URL In IKE Datagram", (500, 500),
     lambda p: "http://" in p.lower()),

    (1000022, "Downloader Payload On 9999", (9999, 9999),
     lambda p: bool(re.search(r"(wget|tftp|curl|busybox)", p, re.I))),

    (1000023, "Downloader Payload On 9034", (9034, 9034),
     lambda p: bool(re.search(r"(wget|tftp|curl|busybox)", p, re.I))),
]


def load_corpus(path):
    rows = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            # Strip CR too: a CRLF checkout would otherwise leave \r on the
            # end of every payload and quietly change what the rules match.
            line = line.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                sys.stderr.write("skipping malformed line: %r\n" % line)
                continue
            rows.append((parts[0], int(parts[1]), "\t".join(parts[2:])))
    return rows


def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv
    rows = load_corpus(CORPUS)

    print("\nRule coverage against %d observed payloads\n" % len(rows))

    uncovered = []
    per_rule = {sid: 0 for sid, _, _, _ in RULES}

    width = max(len(r[0]) for r in rows)
    for name, port, payload in rows:
        hits = []
        for sid, _title, ports, pred in RULES:
            if ports is not None and not (port and ports[0] <= port <= ports[1]):
                continue
            try:
                if pred(payload):
                    hits.append(sid)
                    per_rule[sid] += 1
            except Exception as exc:                      # noqa: BLE001
                sys.stderr.write("rule %d raised on %s: %s\n" % (sid, name, exc))

        flag = "  " if hits else "<-"
        print("%s %-*s  %s" % (flag, width, name,
                               " ".join(str(h) for h in hits) or "NOTHING"))
        if verbose:
            print("%*s  %s" % (width + 3, "", payload[:120]))
        if not hits:
            uncovered.append((name, payload))

    print("\nPer-rule hit counts:")
    for sid, title, _ports, _pred in RULES:
        bar = "#" * per_rule[sid]
        print("  %-8d %-38s %2d %s" % (sid, title, per_rule[sid], bar))

    if uncovered:
        print("\n%d payload(s) matched by NO content rule:" % len(uncovered))
        for name, payload in uncovered:
            print("  %s" % name)
            print("    %s" % payload[:160])
        print("\nNote: a payload with no content-rule hit may still be caught")
        print("by a header-based kit rule (1000010/1000011) or by a structural")
        print("vector rule (1000020), neither of which this script models.")
        return 1

    print("\nevery observed payload is matched by at least one content rule")
    return 0


if __name__ == "__main__":
    sys.exit(main())
