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

### Two places the keys can land, and why it matters

Observed on SO 3.3.0:

| field | type | accepts arbitrary keys? |
|---|---|---|
| `rule.metadata.<key>` | keyword | **only the mapped set** — the standard ET keys (`attack_target`, `signature_severity`, `mitre_*`, `deployment`, `created_at`, `cve`, `tag`, …) |
| `suricata.eve.alert.metadata.<key>` | `flattened` | **yes** — a flattened field indexes whatever keys arrive |

`delivery_class`, `delivery_kit` and `vector` are **not** ET-standard keys, so
whether they appear under `rule.metadata.*` depends on the grid's ingest
pipeline and dynamic mapping. The flattened field does not have that problem.

So: after installing, check which form works on your grid and use that one.

```
# try this first - guaranteed to accept custom keys
suricata.eve.alert.metadata.delivery_class:single_packet_udp

# nicer if the pipeline maps it, but do not assume it
rule.metadata.delivery_class:single_packet_udp
```

The ET-standard keys in these rules (`signature_severity`, `mitre_technique_id`,
`attack_target`, `deployment`, `created_at`) will map to `rule.metadata.*`
either way, which is part of why they are set.

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
