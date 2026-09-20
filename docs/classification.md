# Classification scheme

The point of this scheme is that an analyst, or a query, can answer "was this
a single-packet UDP exploit delivery?" without knowing anything about the
source IP, and can group deliveries by vector and by delivery kit without
knowing family names.

## The defect this replaces

Before these rules, non-Realtek UDP deliveries reached Elasticsearch only when
the source IP happened to be on a reputation list. That produces documents
where:

| field | value | problem |
|---|---|---|
| `rule.name` | `ET DROP Dshield Block Listed Source group 1` | describes the sender, not the packet |
| `rule.category` | `Misc Attack` | same bucket as a port scan |
| `event.severity` | low / informational | a root command injection rated as noise |
| `network.data.decoded` | the actual exploit | present only by accident |

Three consequences: classification is source-derived, payload retention is a
side effect of an unrelated rule, and a clean-source sender of the identical
payload leaves nothing but a Zeek `conn` row.

## SID blocks

Security Onion reserves `1000000+` for local rules. Within that:

| block | meaning | fires on |
|---|---|---|
| `10000xx` | generic content | a downloader verb in any UDP payload, any port |
| `10001xx` | delivery kit | packet-crafting fingerprints, independent of content |
| `10002xx` | vector-specific | known target service plus known payload shape |

The three blocks answer different questions and are meant to overlap. A
delivery that trips `1000011` (kit + downloader) and `1000020` (Easydisc
networkId metacharacter) is better understood than one that trips either
alone.

## Naming

```
LOCAL IOT-DELIVERY <transport> <what matched>
```

`LOCAL` prefixes every rule here, so `rule.name:LOCAL*` isolates local work
from ETOPEN's 67,000 rules in Hunt. `IOT-DELIVERY` is the family of detections,
not the malware family — see below.

## classtype

| classtype | used for | renders as |
|---|---|---|
| `attempted-admin` | delivery of a command that runs as root on the target | Attempted Administrator Privilege Gain |
| `trojan-activity` | kit fingerprint with no payload evidence | A Network Trojan was detected |

Both are low-volume categories on a typical grid, so they stay meaningful.
Nothing here uses `misc-attack`, which is where the reputation rules land and
is effectively unsearchable.

## Metadata — the pivot keys

`metadata:` entries reach Elasticsearch only if the Suricata eve alert output
has `metadata` enabled (`yes`/`true`). Check with `so-udp-delivery check`;
without it, this entire scheme degrades to matching on rule-name substrings.

### Where the keys land

**Settled on SO 3.3.0 against live alerts: use `rule.metadata.*`.** The ingest
pipeline maps custom keys dynamically, so `delivery_class`, `delivery_kit` and
`vector` all arrive there despite not being ET-standard:

```
rule.metadata.delivery_class:single_packet_udp     -> 6 hits
suricata.eve.alert.metadata.delivery_class:...     -> 0 hits
```

The `suricata.eve.alert.metadata` field is mapped `flattened` and would accept
arbitrary keys, but on this grid the alerts do not populate it. Check once on
a new grid rather than assuming either way.

| key | values | what it is for |
|---|---|---|
| `delivery_class` | `single_packet_udp` | the entry criterion itself. One query returns every delivery of this shape regardless of port, vector or family. |
| `delivery_kit` | `d431` | the packet-crafting tool. Links deliveries that share a sender implementation across unrelated vectors. |
| `vector` | `realtek_sdk`, `zyxel_ike`, `ruijie_easydisc`, `udp9999` | the targeted service. |
| `signature_severity` | `Major`, `Critical` | `Critical` is reserved for composite matches — kit plus payload. |
| `mitre_technique_id` | `T1190`, `T1105`, `T1059`, `T1222`, `T1027` | standard mapping. |

## Family attribution does not belong in the rule name

Malware family names, staging hosts and dropper filenames rotate. The delivery
shape does not. A rule named for a family is wrong within weeks and produces
confidently mislabelled alerts in the meantime.

So: **Suricata detects the class, something else attributes the family.**
Attribution belongs in a threat-intel list keyed on staging IP, or in a Sigma
correlation over the resulting alerts. If you want per-family alerting, build
it on top of `rule.metadata.vector` plus infrastructure indicators, not on the
signature.

The one exception is `delivery_kit`, which is a property of the sender's code
rather than of a campaign, and is stable enough to encode.

Live evidence for this, 2026-09-20: one staging host serves byte-identical
payloads under at least three operator tags — `geico`, `victoria` and
`magicdvr`. The tag is `argv[1]`, reported to C2 as the bot's provenance, and
it varies per campaign.

Be careful what the tags are evidence *of*. `geico` is tied to a known exploit
vector because we captured the delivery datagram on UDP/43562. `victoria` and
`magicdvr` were seen only in scripts the staging host serves from its own
TCP/23 and TCP/2222 listeners — that is the **drop** stage, fetched outbound
by a host that has already been exploited by some other means, the same
architecture as the raw-ELF ports 7000-7016. Those ports are not exploit
vectors and the upstream vector for those two campaigns is unknown.

The naming point stands regardless: a rule named for any one tag would have
been wrong for the other two, against identical binaries.

## Known false-positive class: SID 1000010

The bare kit fingerprint matches any raw-socket sender using IP ID 54321 with
DF clear and a zero UDP checksum. That includes amplification-reflection
scanners, which is not a delivery. Observed 2026-09-20: a source sweeping
UDP/389, UDP/53 and UDP/3702 (WS-Discovery) tripped `1000010` with a 3-byte
payload and no downloader verb.

This is the rule working as designed — 54321 is a common raw-socket constant,
so a bare hit means "some crafting kit", never a family. The composite
`1000011` requires a downloader verb as well and correctly did not fire.

If the scanner noise outweighs the value of catching unknown vectors, narrow
`1000010` with `dsize:>40` or exclude the well-known amplification ports
(`53`, `123`, `389`, `1900`, `3702`, `11211`). Do not remove it — catching a
vector nobody has characterised yet is the entire point of that layer.

## Worked queries

Every delivery of this shape, last 7 days, regardless of who sent it:

```
rule.metadata.delivery_class:single_packet_udp
```

Which vectors are actually being attempted, and how often:

```
rule.metadata.delivery_class:single_packet_udp | groupby rule.metadata.vector
```

The bias measurement — deliveries that only a reputation rule caught:

```
event.dataset:alert AND network.transport:udp
  AND rule.name:(ET DROP* OR ET CINS*)
  AND NOT rule.name:LOCAL*
```

Sources sharing a delivery kit across different vectors:

```
rule.metadata.delivery_kit:d431 | groupby source.ip, destination.port
```
