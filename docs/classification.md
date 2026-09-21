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
| `signature_severity` | `Informational`, `Major`, `Critical` | `Critical` is reserved for composite matches — kit plus command. `Informational` marks reconnaissance. |
| `worm_stage` | `reconnaissance`, `exploitation`, `delivery`, `ingress_tool_transfer`, `payload_preparation`, `execution`, `evasion` | position on the Mirai-lineage kill chain. See below. |
| `mitre_technique_id` | `T1595`, `T1190`, `T1105`, `T1059.004`, `T1222.002`, `T1027` | see the worm-chain table below for which rule carries which. |

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

## Measured false-positive class: SID 1000010 is a recon detector

Three days of live traffic, 143 alerts. **39 of the 53 `1000010` hits were
internet-wide reconnaissance, not delivery** — and every one carried a
protocol-*valid* probe for the port it hit:

| port | probe |
|---|---|
| 53 | DNS query for `Dns-UDP-sCaN-0.iO.INTerNEtdATa.Io` — names itself |
| 123 | NTP client packet |
| 161 | SNMP get, community `public` |
| 389 | CLDAP `objectclass` search |
| 427 | SLP service request |
| 443 | full QUIC CHLO, SNI `www.google.com` |
| 500 / 1194 | IKE / OpenVPN handshake openers |
| 1434 | MSSQL ping (1 byte) |
| 1900 | SSDP `M-SEARCH` |
| 3478 | STUN binding request |
| 3702 | WS-Discovery, ONVIF `<tds:GetDeviceInformation />` |
| 5060 / 5061 / 15060 | SIP `OPTIONS`, one with `User-Agent: SIP Scanner` |
| 5683 | CoAP `.well-known/core` |
| 12346…13046 | one identical 64-byte probe across a sequential port sweep |

Sources were overwhelmingly scan infrastructure — Hurricane Electric
(`64.62.197.x`, `74.82.47.x`, `216.218.206.x`, `184.105.247.238`) and AWS
(`100.29.192.x`).

**Size does not separate them.** The QUIC probe is ~700 bytes and the SIP ones
~400 — larger than several genuine deliveries, including the 125-byte
`realtek.selfrep` one-liner. An earlier suggestion in this document to add
`dsize:>100` was wrong and has been removed.

What separates them is simple: **a delivery carries a command, a probe carries
a protocol.** That is exactly what `1000011` tests, and it is why `1000011`
had *zero* false positives over the same period against `1000010`'s 39.

So `1000010` is reclassified rather than tuned. As of rev:2 it is
`classtype:network-scan`, `signature_severity Informational`, mapped to
**TA0043 / T1595 (Active Scanning)**, and renamed to say "Recon Or Delivery".
It stays enabled — it is still the only rule that can see a vector nobody has
characterised yet — but it is scored as what it actually finds.

### Bidirectional traffic: checked, not a factor

Tested explicitly: no host in `192.168.0.0/16`, `10.0.0.0/8` or
`172.16.0.0/12` contacted any of these sources in the same three days, so none
of the hits are replies to internally-initiated traffic. Inbound to the
internal range in that window was ICMP and TCP only — **zero UDP** — so NAT
produces no duplicate UDP alerts either.

The exposure was real even though it did not materialise: `1000010` and
`1000011` had no `flow:to_server`, so a reply from an external server carrying
the same header fingerprint would have matched. Both carry it as of rev:2.

## Mapping to the documented worm chain

Every rule now carries a `worm_stage` key placing it on the Mirai-lineage kill
chain these families all follow — scan, exploit, fetch, make executable,
execute, tidy up:

| stage | SIDs | ATT&CK |
|---|---|---|
| `reconnaissance` | `1000010` | TA0043 / T1595 |
| `exploitation` | `1000020`–`1000023` | TA0001 / T1190 |
| `delivery` | `1000011` | TA0001 / T1190 + T1105 |
| `ingress_tool_transfer` | `1000001`–`1000004`, `1000008` | TA0011 / T1105 |
| `payload_preparation` | `1000005` | TA0005 / T1222.002 |
| `execution` | `1000006` | TA0002 / T1059.004 |
| `evasion` | `1000007` | TA0005 / T1027 |

This corrected a real error. The generic downloader rules were tagged
**TA0001 / T1190 (Exploit Public-Facing Application)**, which conflated
fetching a payload with exploiting a service. Fetching is **T1105 Ingress Tool
Transfer** under **TA0011 Command and Control**; only the vector-specific
rules exploit anything. `chmod` was tagged TA0002 when `T1222.002` is Defense
Evasion.

```
rule.metadata.worm_stage:exploitation
rule.metadata.worm_stage:ingress_tool_transfer
rule.name:LOCAL* | groupby rule.metadata.worm_stage
```

A source appearing at several stages from one datagram is the normal case for
this class — a single geico delivery trips exploitation, delivery, transfer
and execution at once, because the entire chain is in one packet. That is the
property that makes it visible to a passive sensor at all.

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
