# Deployment

Two routes. Both end with the same detections on the grid; pick whichever
matches how you already manage Security Onion.

## Route A — the CLI (file-based)

Runs on the manager, writes into the grid's local rules location, applies the
salt state.

```bash
git clone https://github.com/graphworlok/so-udp-delivery-detections
cd so-udp-delivery-detections

sudo ./bin/so-udp-delivery check              # read-only survey. Start here.
sudo ./bin/so-udp-delivery test               # suricata -T syntax validation
sudo ./bin/so-udp-delivery install --confirm
sudo ./bin/so-udp-delivery deploy  --confirm
sudo ./bin/so-udp-delivery verify
```

Every mutating command is a **dry run without `--confirm`**, and every write is
backed up to `.backups/` first. Rules land inside a marked block:

```
# BEGIN so-udp-delivery-detections v1.0.0 (installed ...)
...
# END so-udp-delivery-detections
```

so reinstalling replaces cleanly and `remove` restores the file without
touching anything else that happens to live in `local.rules`.

### Path discovery

Security Onion has moved the local-rules location between releases, so the CLI
probes rather than assumes, in this order:

```
/opt/so/saltstack/local/salt/idstools/rules/local.rules
/opt/so/saltstack/local/salt/idstools/local.rules
/opt/so/rules/nids/local.rules
/nsm/rules/local.rules
```

An existing file wins; otherwise the first candidate whose parent directory
exists. `check` prints which one it chose. **If none is found, or the one it
picked is wrong for your release, pass `--rules-path` explicitly** — do not let
it guess. Same approach for the Sigma directory and `suricata.yaml`.

## Route B — the SOC Detections UI

If you would rather manage these through SOC, or the file-based path is not
available on your release:

```bash
./bin/so-udp-delivery export-soc > detections.ndjson
```

This emits one `so-detection` document per rule, in the schema SOC actually
stores custom detections in (`ruleset: __custom__`, `isCommunity: false`,
`publicId` = the SID for Suricata and the rule UUID for Sigma, `content` = the
raw rule text).

You can also simply paste individual rules into **SOC → Detections → New
Detection**, language `suricata` or `sigma`. That is the lowest-risk route for
a first rule, and it is how the four existing custom Sigma detections on this
grid were created.

## Configuration these detections depend on

`so-udp-delivery configure` prints this; it does not edit pillar files, because
pillar changes affect the whole grid and deserve to be hand-applied.

### 1. `payload: yes` and `metadata: yes` on the eve alert output

For single-packet UDP, **the alert is the capture**. Without `payload: yes` the
datagram bytes never reach Elasticsearch and you have a detection that tells
you something happened but not what. Without `metadata: yes` the
`delivery_class` / `delivery_kit` / `vector` keys never become
`rule.metadata.*` fields and the classification scheme collapses.

### 2. `checksum-validation: none`

Suricata skips rule evaluation on packets with bad checksums by default. Some
of the traffic these rules target carries deliberately malformed checksums —
which means the default silently drops exactly the packets you care about, and
the failure looks identical to "the rule doesn't work".

Note this is separate from the zero UDP checksum in the kit fingerprint. A
zero UDP checksum is legal in IPv4 and means "not computed", so it is not
treated as invalid.

### 3. HOME_NET must contain the monitored WAN address

Every rule here is written `-> $HOME_NET`. If the monitored WAN IP is outside
HOME_NET, nothing fires and there is no error to notice. On a grid with NAT
double-logging this is worth checking rather than assuming. `check` prints the
running value.

## Rollback

```bash
sudo ./bin/so-udp-delivery remove --confirm
sudo ./bin/so-udp-delivery deploy --confirm
```

Backups are in `.backups/` with UTC timestamps. The managed-block markers mean
removal is exact — it does not rely on matching rule text.
