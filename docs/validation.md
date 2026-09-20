# Validation

A detection you have not seen fire is a hypothesis. These rules target traffic
that arrives unpredictably, so waiting for the next live delivery is a bad
feedback loop. Replay a known-good capture instead.

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
