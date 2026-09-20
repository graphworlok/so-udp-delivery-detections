# so-udp-delivery-detections

Security Onion detections for **single-packet UDP exploit delivery** — the
class of attack where one unsolicited datagram carries both the exploit and
its downloader, needing no listener, no handshake and no reply.

## Why this class is special

A passive sensor sees the entire exploit whether or not anything on the
monitored side would have answered. There is no handshake to complete, so
there is nothing to miss. CVE-2021-35394 (Realtek SDK, UDP/9034) is the
best-known example, but the property belongs to the *delivery shape*, not to
that one CVE — the same self-contained `wget|tftp|…|sh` one-liner arrives on
UDP/500 (Zyxel IKE), UDP/9999, and UDP/43562 (Ruijie Reyee Easydisc), among
others.

Every other vector these senders use needs a completed TCP handshake, and is
therefore invisible to a passive sensor. So this class is not just detectable —
for a passive grid it is frequently the *only* thing that is.

## The problem this repo solves

On a stock grid, only the Realtek vector has an exploit signature. Every other
single-packet UDP delivery surfaces **only when the source IP happens to be on
a reputation list** (`ET DROP Dshield`, `ET CINS`). That means:

- **Classification is source-derived, not content-derived.** A root command
  injection is filed as `Misc Attack` at low severity, described by who sent
  it rather than by what it was.
- **Payload retention is an accident.** The datagram bytes reach Elasticsearch
  only because an unrelated rule fired. Zeek logs the `conn` row but not the
  payload.
- **A clean-source sender of the identical payload is invisible**, and you
  cannot measure how often that happens.

These rules make the content and the packet construction the trigger, so the
reputation list stops being load-bearing.

## What's here

```
rules/suricata/udp-delivery.rules   13 rules, SID block 1000000-1000999
rules/sigma/                        2 rules - the payload-free metadata half
bin/so-udp-delivery                 configure / install / validate CLI
hunts/udp-delivery.hunts            Hunt queries, runnable not quoted
docs/classification.md              SID blocks, naming, classtype, metadata pivots
docs/deployment.md                  both install routes + required grid config
docs/validation.md                  so-import-pcap positive-control loop
```

Three detection layers, deliberately overlapping:

| layer | SIDs | independent of | catches |
|---|---|---|---|
| generic content | `10000xx` | source reputation, port | any downloader verb in a UDP payload |
| delivery kit | `10001xx` | source reputation, **payload content** | vectors not yet identified |
| vector-specific | `10002xx` | source reputation | known service + known payload shape |

The delivery-kit layer is the one worth understanding. IP ID `0xd431` with the
DF bit clear and a zero UDP checksum is a raw-socket sender that never computed
a checksum — a property of the attacker's *tooling*, not of any payload. It
fires on ports nobody has characterised yet, which is how a new vector
announces itself rather than being discovered later by reverse engineering.

## Quick start

```bash
sudo ./bin/so-udp-delivery check     # read-only survey. Always start here.
sudo ./bin/so-udp-delivery test      # suricata -T validation
```

`check` then tells you which install route applies, and it is not a
preference:

**On Security Onion 2.4+** Suricata loads one SOC-generated rules file built
from the `so-detection` index (confirmed on 3.3.0: `rule-files:` contains only
`all-rulesets.rules`). A hand-written `local.rules` has no effect and raises no
error, so `install` refuses to write one. Use the Detections UI:

```bash
./bin/so-udp-delivery export-soc --format text   # paste-friendly, per rule
```

Paste each into SOC → Detections → New Detection, ruleset `__custom__`. Start
with `1000010`, `1000001` and `1000020` rather than all thirteen —
`docs/deployment.md` says why.

**On older releases** where `local.rules` is in `rule-files:`:

```bash
sudo ./bin/so-udp-delivery install --confirm
sudo ./bin/so-udp-delivery deploy  --confirm
sudo ./bin/so-udp-delivery verify
```

Every mutating command is a dry run without `--confirm`. Rules install inside
a marked block with a backup taken first, so `remove` is exact.

## Three settings decide whether any of this works

`so-udp-delivery check` reports all three, and then checks the first two
again **empirically** against what actually reached Elasticsearch. Where the
config parse and the empirical check disagree, the empirical check is right —
key names and value spellings move between releases, and a false negative here
sends you off fixing something that was never broken.

1. **`payload-printable` on the eve alert output.** This is what populates
   `network.data.decoded`, the field every hunt here reads — for single-packet
   UDP the alert *is* the capture. Verify with `_exists_:network.data.decoded`
   in Hunt. Plain `payload` adds a raw base64 copy: worth having for byte-exact
   work on binary vectors, but not a blocker.
2. **`metadata` on the same output.** Carries `delivery_class` /
   `delivery_kit` / `vector` through to Elasticsearch. Note these are not
   ET-standard keys — see `docs/classification.md` for which field they land
   in, because it is not always `rule.metadata.*`.
3. **HOME_NET contains the monitored WAN address.** Every rule is written
   `-> $HOME_NET`, and single-packet delivery is addressed to the public WAN
   IP. If that address is outside HOME_NET, nothing fires and nothing errors.

Also check `checksum-validation` — Suricata skips rule evaluation on
bad-checksum packets by default, and some crafted delivery traffic carries
deliberately malformed checksums. It is a boolean (`true`/`false`); `none` is
not valid there.

## Status and caveats

Read these before trusting a rule.

- **The rules have not yet been run against live Suricata.** `so-udp-delivery
  test` does that, and it should be the first thing you run on the manager.
- **The Easydisc offsets (SID 1000020) are capture-derived**, not read out of
  a struct definition. Validate with `import-pcap` against a known Easydisc
  datagram before trusting them; `docs/validation.md` says what to check.
- **The file-based install route does not work on SO 2.4+.** Confirmed on
  3.3.0: Suricata loads only `all-rulesets.rules`, generated by SOC from the
  `so-detection` index. `check` parses `rule-files:` and says so, and `install`
  refuses to write to an unloaded path. Use `export-soc`.
- **Custom metadata keys may not reach `rule.metadata.*`.** On SO 3.3.0 that
  field maps the ET-standard key set; `suricata.eve.alert.metadata` is
  `flattened` and takes arbitrary keys. Check which works before building
  saved queries on either.

Confirmed against a live SO 3.3.0 grid: the `so-detection` schema `export-soc`
emits, `zeek.conn` / `source.packets` / `destination.packets`, and that payload
and rule metadata do reach Elasticsearch there.

## Relationship to other work

This repo is detection engineering only. The reverse engineering that produced
the vector list, the byte offsets and the `0xd431` kit fingerprint lives
separately, in a private research repo, and is not required to use any of this.

Family attribution is deliberately **not** encoded in rule names — names,
staging hosts and dropper filenames rotate, the delivery shape does not. See
`docs/classification.md`.
