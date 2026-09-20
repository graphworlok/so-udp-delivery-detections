# Validation

A detection you have not seen fire is a hypothesis. These rules target traffic
that arrives unpredictably, so waiting for the next live delivery is a bad
feedback loop. Replay a known-good capture instead.

## so-suricata-testrule — the tool to use

Security Onion ships `/usr/sbin/so-suricata-testrule`, and it is better suited
to this than anything this repo could build:

```
so-suricata-testrule <CustomRule> <TargetPCAP>
```

It copies `/opt/so/rules/suricata/all-rulesets.rules` to a scratch directory,
**appends** your rule file to that copy, and runs Suricata over the pcap in a
container with the right mounts. Two properties matter here:

- **The live ruleset is not touched.** It works on a copy, so a broken rule
  cannot affect the running sensor.
- **Your rules are tested alongside the full production ruleset**, so SID
  collisions and interactions surface, not just standalone syntax.

`so-udp-delivery test` wraps it. With no argument it generates a self-test
capture (below) so the run is a positive control rather than a bare syntax
check. Given a pcap, it runs the rules against that instead:

```bash
sudo ./bin/so-udp-delivery test                      # self-test capture
sudo ./bin/so-udp-delivery test /tmp/delivery.pcap   # a real capture
```

`test` reads the verdict from Suricata's own rule-loading summary, not from
the exit code — the exit code also covers the pcap stage, which can fail for
reasons unrelated to the rules.

## The self-test capture

With no pcap argument, `test` generates one via `tools/make-selftest-pcap.py`:
two crafted datagrams carrying the `0xd431` kit fingerprint (IP ID, DF clear,
TTL 232, zero UDP checksum) and a `wget`/`chmod` one-liner, to UDP/9034 and
UDP/9999. Nothing is transmitted; the URL is in TEST-NET-3.

Confirmed on SO 3.3.0 / Suricata 8.0.6 — 9 alerts across 6 SIDs:

| SID | 9034 | 9999 | note |
|---|---|---|---|
| `1000001` wget | ✓ | ✓ | |
| `1000005` chmod +x | ✓ | ✓ | |
| `1000010` kit fingerprint | ✓ | — | thresholded 1 per source per 600s, so the second packet is correctly suppressed |
| `1000011` kit + downloader | ✓ | ✓ | |
| `1000022` UDP/9999 | — | ✓ | |
| `1000023` UDP/9034 | ✓ | — | |

The destination is `192.168.1.10`, so it only matches where HOME_NET covers
RFC1918. If the rules parse but nothing fires, that is the first thing to
check:

```bash
python3 tools/make-selftest-pcap.py --dst <ip-inside-HOME_NET> /tmp/st.pcap
sudo ./bin/so-udp-delivery test /tmp/st.pcap
```

**SID 1000020 (Easydisc) is not covered by the self-test** and remains the one
unproven rule — see below.

## Positive control via so-import-pcap

`so-import-pcap` replays a pcap through Suricata and Zeek and indexes the
results, which gives a deterministic yes/no for every SID before it goes live.

```bash
# carve one known delivery datagram out of retained pcap
tcpdump -r /nsm/pcap/<file>.pcap -w /tmp/delivery.pcap \
    'udp and host <source> and port <vector-port>'

sudo ./bin/so-udp-delivery import-pcap /tmp/delivery.pcap --confirm
```

`so-import-pcap` prints a Hunt URL scoped to the import. **Imported events keep
the pcap's original timestamps**, so search that range, not `now` — this is the
single most common reason an import looks like it produced nothing.

Confirm for each imported datagram:

1. the expected SID fired,
2. `network.data.decoded` contains the one-liner,
3. `rule.metadata.delivery_class` is populated — if the alert is there but the
   metadata is not, `metadata: yes` is missing from the eve config.

## What to replay

One capture per row, at minimum:

| vector | expected SIDs |
|---|---|
| Realtek SDK, UDP/9034 | `1000001`/`1000002` + `1000023` |
| Ruijie Easydisc, UDP/43562 | `1000020`, plus `1000010`/`1000011` if the kit matches |
| Zyxel IKE, UDP/500 | `1000021` + a generic content rule |
| UDP/9999 | `1000022` + a generic content rule |

The Easydisc rule is the one most likely to fail, because its byte offsets are
capture-derived rather than read out of the firmware's struct definition:

```
+0    16-byte salted MD5 prefix
+16   msg_type (0x40)
+20   filler running up to the command placement
+352  networkId (struct+0x150), ~32 bytes usable
```

If `1000020` does not fire on a capture you know is an Easydisc exploit, check
those offsets against the captured bytes before assuming the rule is wrong in
concept. The `dsize:>360` bound may also need widening if a variant is smaller.

## Negative control — false positives

The generic content rules run against **all** UDP, including high-port QUIC.
That is deliberate, and it is also where false positives will come from.

Never match a bare `|sh` — encrypted QUIC payloads produce it by chance at high
volume. Every rule here requires a fetch verb plus a second token for that
reason. After a week, check what actually matched:

```
rule.name:LOCAL* | groupby rule.name, source.ip, destination.port
```

Expect near-zero volume. If a rule is noisy, the fix is a tighter second
anchor, not a higher threshold — thresholds suppress the payload capture too,
which is the thing you are trying to keep.

## The measurement that matters

The reason to deploy these at all is to find out how much you were missing.
Before the content rules, every non-Realtek delivery in this grid arrived
labelled as a reputation hit. After, compare:

```
# deliveries the content rules caught
rule.metadata.delivery_class:single_packet_udp

# of those, how many ALSO had a reputation hit from the same source
rule.metadata.delivery_class:single_packet_udp AND source.ip:(...)
```

The gap between them is the clean-source population — deliveries that would
have been invisible. That number is the answer to "how biased is this dataset",
and until the content rules exist it cannot be measured at all.
