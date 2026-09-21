# Deployment

Two routes. **Which one applies is not a preference — it depends on your
release, and `so-udp-delivery check` tells you which.**

On Security Onion 2.4 and later, Suricata loads a single SOC-generated rules
file built from the `so-detection` index. Confirmed on SO 3.3.0:

```
default-rule-path: /etc/suricata/rules
rule-files:
  - all-rulesets.rules
```

`local.rules` is not in that list, so writing one has **no effect and produces
no error** — the install looks fine and nothing ever fires. On such a grid,
Route B is the only route that works, and `install` refuses to run.

Run `check` first. It parses `rule-files:` out of `suricata.yaml` and says
directly whether the file route is viable.

## Step 0 — getting the files onto the manager

**This repo is private**, so an unauthenticated `git clone` on the manager will
fail. Three ways round it, in increasing order of how much you are committing
to:

**Copy them over.** Nothing needs to persist on the manager, and this leaves no
credentials on a sensor:

```bash
# from the workstation that has the clone
rsync -av --exclude .git ./so-udp-delivery-detections/ \
    <user>@<manager>:~/so-udp-delivery-detections/
```

**A read-only deploy key**, if you want `git pull` on the manager to work:

```bash
# on the manager
ssh-keygen -t ed25519 -f ~/.ssh/so-udp-delivery -N ''
cat ~/.ssh/so-udp-delivery.pub
# add that key at: Settings -> Deploy keys -> Add deploy key (leave write access off)
GIT_SSH_COMMAND='ssh -i ~/.ssh/so-udp-delivery' \
    git clone git@github.com:graphworlok/so-udp-delivery-detections.git
```

**`gh auth login` on the manager.** Works, but it puts a token with access to
every private repo on the account onto a sensor. Prefer one of the above.

Whichever route, make the scripts executable after transfer — rsync preserves
the bit, a zip download does not:

```bash
chmod +x bin/so-udp-delivery tests/test-rules.sh
```

## Route A — the CLI (file-based)

Runs on the manager, writes into the grid's local rules location, applies the
salt state.

```bash
cd ~/so-udp-delivery-detections

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

## Route B — the SOC Detections UI (required on 2.4+)

Custom detections live in the `so-detection` index and SOC compiles them into
the rules file Suricata loads. That makes the UI the supported input, and on
2.4+ the only one.

**Paste-friendly output**, one rule per block with its SID and title:

```bash
./bin/so-udp-delivery export-soc --format text
```

For each block: **SOC → Detections → New Detection**, language `suricata` (or
`sigma` for the YAML blocks), paste, leave the ruleset as `__custom__`, save.
This is how the four existing custom Sigma detections on this grid were
created.

**Machine-readable output**, one `so-detection` document per line in the
schema SOC stores them in (`ruleset: __custom__`, `isCommunity: false`,
`publicId` = the SID for Suricata and the rule UUID for Sigma, `content` = the
raw rule text):

```bash
./bin/so-udp-delivery export-soc > detections.ndjson
```

### Do them in stages, not all thirteen

Pasting 13 rules in one sitting means 13 untested rules landing together. Start
with three, in this order — they cover the most ground and are the least likely
to be noisy:

| SID | why first |
|---|---|
| `1000010` | kit fingerprint. Independent of payload and source, catches unknown vectors. Lowest false-positive risk in the set. |
| `1000001` | the generic `wget` content rule. Highest expected hit rate. |
| `1000020` | Easydisc. The one with capture-derived offsets, so it most needs a live test. |

Let those run for a day, check volume with `rule.name:LOCAL* | groupby
rule.name`, then add the rest.

### Writing to so-detection directly

Use the UI for a first install. Direct writes to the index are possible and
are what Security Onion's own tooling does, but they skip the validation SOC
runs on save — see the appendix at the end of this document for the mechanism,
the exact document shape, and when it is worth the risk.

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

## Appendix: is a CLI push possible after all?

Revisited 2026-09-21 with read access to the manager. Short answer: yes,
mechanically — but it is not a supported interface, and the UI stays the safe
path.

### What the grid actually shows

`so-detections-overrides-import`, which Security Onion ships, is the proof:

```python
AUTH_FILE = "/opt/so/conf/elasticsearch/curl.config"
ES_URL    = "https://localhost:9200"

def make_session(auth_file):
    for line in open(auth_file):
        if line.startswith("user ="):
            creds = line.split("=", 1)[1].strip().replace('"', "")
            user, _, password = creds.partition(":")
            ...HTTPBasicAuth(user, password)

r = session.get(f"{ES_URL}/{index}/_search", json=query)      # find
r = session.post(f"{ES_URL}/{doc_index}/_update/{doc_id}", …) # change
```

So SO's own tooling reads basic-auth creds from `curl.config` and mutates
`so-detection` over Elasticsearch REST. Writing to that index directly is
therefore consistent with how the product operates — it is not a hack around
SOC.

The important limits:

- That tool handles **overrides only** (suppress / threshold / modify on a
  detection that already exists). Nothing shipped **creates** a detection.
- `curl.config` is root-readable only, so any such tool needs `sudo`.
- `so-*` has no other detection tooling: the full list contains
  `so-detections-overrides-import` and `so-detections-runtime-status`, and the
  latter only greps elastalert errors for Sigma.

### The document to write

Read back from a detection SOC created through the UI (SID 1000010), so this
is SOC's own shape rather than a guess:

| field | value |
|---|---|
| `_id` | a fresh UUID |
| `so_detection.publicId` | the SID |
| `so_detection.engine` / `.language` | `suricata` |
| `so_detection.ruleset` | `__custom__` |
| `so_detection.isCommunity` | `false` |
| `so_detection.isEnabled` | `true` |
| `so_detection.isReporting` | `false` |
| `so_detection.content` | the full rule, one line |
| `so_detection.severity` | `critical` if the rule carries `signature_severity Critical`, else `high` |
| `so_detection.description` | SOC writes `Detection description not yet provided` |
| `so_detection.license` | SOC writes `AGPL-3.0-only` |
| `so_detection.sourceCreated` | midnight of the rule's `created_at` |
| `so_detection.userId` | the Kratos user id SOC stamped; copy it from an existing custom detection |
| `so_detection.overrides` | `[]` |
| `so_detection.tags`, `.sourceUpdated` | `null` |

Note there is **no** `so_detection.category` on a custom detection — SOC sets
that only for community rulesets like ETOPEN. `export-soc` currently emits
one, which is harmless but not faithful.

### Why the UI is still the right default

- A direct write bypasses the validation SOC runs when you save a rule. A bad
  document lands in the datastore and, at worst, stops the ruleset compiling.
- SOC's caching behaviour on externally-inserted documents is unverified. The
  overrides tool implies SOC re-reads the index, but that is inference, not a
  tested guarantee for *creation*.
- The schema belongs to SOC and can change on upgrade.

Where it earns its keep is **repeatability**, not first install: rev bumps
across several rules, tuning changes, or rebuilding a grid from this repo.
Clicking through thirteen rules once is fine; doing it after every edit is
not.

### tools/push-soc.py

That tool now exists. It validates nothing itself by design — run
`so-udp-delivery test` first — and otherwise: dry run by default, diffs
against what SOC already holds so unchanged rules are skipped, creates with
`PUT _doc/<uuid>?refresh=true`, updates with `POST _update/<id>?refresh=true`,
and copies the `userId` from an existing custom detection so ownership stays
consistent.

```bash
# see what would change; writes nothing
sudo python3 tools/push-soc.py rules/suricata/udp-delivery.rules

#   CREATE  1000008  rev:2  LOCAL IOT-DELIVERY UDP Single-Packet Netcat Fetch
#   UPDATE  1000005  rev:1 -> 2  LOCAL IOT-DELIVERY UDP ... Executable Bit
#   same    1000001  rev:1
#   ...

# apply just the two that changed
sudo python3 tools/push-soc.py rules/suricata/udp-delivery.rules     --sid 1000005 --sid 1000008 --confirm

# then, after SOC recompiles
sudo ./bin/so-udp-delivery verify
```

### Measured result: creates compile, updates do not

Tested on SO 3.3.0, 2026-09-20. A create (`1000008`) and an update
(`1000005` rev:1 -> rev:2) were written to `so-detection` at 23:59:16. SOC
recompiled `all-rulesets.rules` at 00:10:31 — eleven minutes later, with both
changes already in Elasticsearch. Result:

| change | in `so-detection` | in `all-rulesets.rules` |
|---|---|---|
| create `1000008` rev:2 | yes | **yes** |
| update `1000005` to rev:2 | yes | **no** — still rev:1 |

Not a race: the compile ran well after both writes. SOC appears to keep its
own copy of each detection and refresh only what it believes changed. A new
document is unavoidably new so it gets compiled; an edited one is not noticed,
because as far as SOC is concerned nothing changed.

**Creates are noticed; in-place edits are not.** A create is unavoidably new,
so SOC compiles it. So `push-soc` performs an update as a **delete followed by
a create under a fresh document id**, which is the only shape SOC reliably
honours. `createTime`, `userId`, `author`, `isEnabled` and any attached
overrides are carried across from the original.

The costs are honest ones: the document id changes, there is a brief window
where the rule does not exist, and if the create fails after the delete the
tool prints the rule text to paste into the UI. `--in-place` restores the old
`_update` behaviour for comparison; it is not expected to compile.

Always verify:

```bash
grep -c 'sid:<SID>; rev:<N>' /opt/so/rules/suricata/all-rulesets.rules
```

Untested: whether `so-soc-restart` forces a full re-read and picks up external
updates. It plausibly would, but restarting SOC on a production grid to work
around this is a worse trade than clicking Save.

It is deliberately **not** wired into `bin/so-udp-delivery`. Everything the
CLI does is either read-only or reversible from a backup; this is neither, so
it stays a separate deliberate invocation rather than one subcommand among
several.

Rolling back a bad push means deleting the document by `_id` (visible in the
create output) or fixing the rule and pushing again — there is no `.backups/`
equivalent for the index.
