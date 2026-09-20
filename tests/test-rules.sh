#!/usr/bin/env bash
#
# Offline sanity checks. These run anywhere - no Security Onion, no Suricata.
# For real rule validation use: so-udp-delivery test  (runs suricata -T).

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RULES="${REPO_ROOT}/rules/suricata/udp-delivery.rules"
SIGMA_DIR="${REPO_ROOT}/rules/sigma"

pass=0; fail=0
ok()   { printf '  ok   %s\n' "$*"; pass=$((pass+1)); }
bad()  { printf '  FAIL %s\n' "$*"; fail=$((fail+1)); }

printf '\n== structure ==\n'

[[ -f "$RULES" ]] && ok "rules file exists" || bad "rules file missing"

n_rules="$(grep -c '^alert' "$RULES" 2>/dev/null || echo 0)"
[[ "$n_rules" -gt 0 ]] && ok "$n_rules rules found" || bad "no rules found"

printf '\n== every rule is one line ==\n'
if grep -q '\\$' "$RULES"; then
    bad "line continuations present - SOC stores detection content single-line"
else
    ok "no line continuations"
fi

printf '\n== required options on every rule ==\n'
for opt in 'msg:' 'sid:' 'rev:' 'classtype:' 'metadata:'; do
    missing="$(grep '^alert' "$RULES" | grep -vc "$opt" || true)"
    if [[ "$missing" -eq 0 ]]; then
        ok "all rules have $opt"
    else
        bad "$missing rule(s) missing $opt"
    fi
done

printf '\n== SIDs ==\n'
sids="$(grep -oE '\bsid:[0-9]+' "$RULES" | cut -d: -f2 | sort)"
n_sid="$(printf '%s\n' "$sids" | wc -l)"
n_uniq="$(printf '%s\n' "$sids" | sort -u | wc -l)"
[[ "$n_sid" -eq "$n_uniq" ]] && ok "all $n_sid SIDs unique" || bad "duplicate SIDs present"

out_of_range="$(printf '%s\n' "$sids" | awk '$1 < 1000000 || $1 > 1000999' | wc -l)"
[[ "$out_of_range" -eq 0 ]] \
    && ok "all SIDs inside the local block 1000000-1000999" \
    || bad "$out_of_range SID(s) outside the reserved block"

printf '\n== naming convention ==\n'
badname="$(grep '^alert' "$RULES" | grep -vc 'msg:"LOCAL IOT-DELIVERY ' || true)"
[[ "$badname" -eq 0 ]] \
    && ok 'every msg starts with "LOCAL IOT-DELIVERY "' \
    || bad "$badname rule(s) do not follow the naming convention"

printf '\n== classification metadata ==\n'
noclass="$(grep '^alert' "$RULES" | grep -vc 'delivery_class ' || true)"
[[ "$noclass" -eq 0 ]] \
    && ok "every rule carries delivery_class" \
    || bad "$noclass rule(s) missing delivery_class"

printf '\n== the bare |sh trap ==\n'
# A content match on "|sh" with no second anchor false-positives against QUIC.
if grep '^alert' "$RULES" | grep '|7c|sh' | grep -vq 'content:"http"'; then
    bad "a rule matches |sh without also requiring a URL"
else
    ok "no unanchored |sh match"
fi

printf '\n== sigma ==\n'
if command -v python3 >/dev/null 2>&1; then
    for f in "$SIGMA_DIR"/*.yml; do
        [[ -e "$f" ]] || continue
        if python3 -c "import yaml,sys; d=yaml.safe_load(open(sys.argv[1]));
assert d.get('id'), 'no id'
assert d.get('title'), 'no title'
assert d.get('detection'), 'no detection'
assert d.get('logsource'), 'no logsource'" "$f" 2>/dev/null; then
            ok "$(basename "$f")"
        else
            bad "$(basename "$f") - invalid or incomplete"
        fi
    done
else
    printf '  skip python3 not available\n'
fi

printf '\n== coverage against real observed payloads ==\n'
if command -v python3 >/dev/null 2>&1; then
    if python3 "${REPO_ROOT}/tests/coverage.py" >/dev/null 2>&1; then
        ok "every corpus payload matches at least one content rule"
    else
        bad "a corpus payload is matched by NO content rule - run tests/coverage.py"
    fi
else
    printf '  skip python3 not available\n'
fi

printf '\n== cli ==\n'
if bash -n "${REPO_ROOT}/bin/so-udp-delivery" 2>/dev/null; then
    ok "so-udp-delivery parses"
else
    bad "so-udp-delivery has a syntax error"
fi

printf '\n%d passed, %d failed\n\n' "$pass" "$fail"
[[ "$fail" -eq 0 ]]
