#!/usr/bin/env bash
# CI and pre-commit checks for the mod:
#   1. HCL parses and every benchmark, control and dashboard is listable
#   2. Every control carries a agentreach id; SQL template hygiene
#   3. Every SQL block reading an agent-scoped table filters agent =
#      'claude_code' (Codex rows exist and must never be judged by
#      Claude Code rules)
#   4. The release version is wired the same way in mod.pp, README.md,
#      spec/controls.yaml and ci/fixtures.sh
#   5. No credential-shaped files or secret-shaped strings in the tree
#   6. spec/controls.yaml is complete and matches the control tags, the
#      benchmark descriptions and README state the real counts, and
#      docs/coverage.md is current
#   7. The core controls return the expected status on every fixture
#      (ci/fixtures.sh; skipped when Steampipe or the agentreach_fixtures
#      connection is missing)
# Blocking checks exit non-zero. Needs powerpipe on PATH; Steampipe is not
# required (listing does not query the database).
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1
fail=0

say()  { printf '\n\033[1m== %s\033[0m\n' "$1"; }
bad()  { printf '\033[31m  FAIL: %s\033[0m\n' "$1"; fail=1; }
ok()   { printf '\033[32m  ok: %s\033[0m\n' "$1"; }

#### 1. Parse + list ###########################################################
say "powerpipe parse and list"
if ! command -v powerpipe >/dev/null 2>&1; then
  bad "powerpipe not on PATH"
else
  for kind in benchmark control dashboard; do
    if out=$(powerpipe "$kind" list 2>&1); then
      n=$(printf '%s\n' "$out" | grep -c 'agentreach_compliance\.' || true)
      ok "$kind list: $n"
    else
      bad "$kind list failed:"
      printf '%s\n' "$out" | sed 's/^/    /'
    fi
  done
fi

#### 2. Tag completeness #######################################################
say "control tags"
missing=0
# Every control carries a agentreach id.
for f in controls/*.pp; do
  [ "$f" = "controls/benchmark.pp" ] || [ "$f" = "controls/legs.pp" ] && continue
  controls=$(grep -c '^control "' "$f")
  [ "$controls" -eq 0 ] && continue
  have=$(grep -cE '^\s+agentreach\s+=|\bagentreach\s+=\s+"' "$f")
  if [ "$have" -lt "$controls" ]; then
    bad "$f: $have of $controls controls carry tag 'agentreach'"; missing=1
  fi
done
[ "$missing" -eq 0 ] && ok "every control carries a agentreach id"

#### 2b. Template hygiene ######################################################
say "SQL template arguments"
# Text substituted into a single-quoted SQL string must not contain an apostrophe.
if grep -nE '"__(FIX|ABSENT_REASON)__", "[^"]*'"'"'' controls/*.pp; then
  bad "an apostrophe inside a __FIX__/__ABSENT_REASON__ argument would break the SQL string"
else
  ok "no apostrophes in template arguments"
fi
# A control whose SQL uses $1 must declare a param.
noparam=$(awk '
  /^control "/ { name=$2; uses=0; params=0 }
  /\$1/ { uses=1 }
  /^[ \t]*param "/ { params++ }
  /^}/ && name != "" { if (uses && !params) print FILENAME": "name" uses $1 without a param block"; name="" }
' controls/*.pp)
if [ -n "$noparam" ]; then
  printf '%s\n' "$noparam" | while read -r line; do printf '\033[31m  FAIL: %s\033[0m\n' "$line"; done
  fail=1
else
  ok "every control that uses \$1 declares a param"
fi

#### 2c. Agent filter ###########################################################
say "agent = 'claude_code' filter"
if out=$(python3 ci/agent_filter_check.py 2>&1); then
  ok "$out"
else
  bad "SQL blocks reading agent tables without the agent filter:"
  printf '%s\n' "$out" | sed 's/^/    /'
fi

#### 2d. Release version wiring ###############################################
say "release version wiring"
if out=$(python3 ci/version_check.py 2>&1); then
  ok "$out"
else
  bad "the release version is not wired the same way everywhere:"
  printf '%s\n' "$out" | sed 's/^/    /'
fi

#### 3. No secrets #############################################################
say "no credential files or secret-shaped strings"
hits=$(git ls-files -co --exclude-standard \
  | grep -E '(^|/)\.env($|\.)|\.spc$|(^|/)credentials(\.|$)|\.pem$|\.p12$|id_rsa|\.pps$|\.ppvars$' || true)
if [ -n "$hits" ]; then
  bad "credential-shaped files present:"
  printf '%s\n' "$hits" | sed 's/^/    /'
else
  ok "no credential-shaped files"
fi
if git grep -nIE '(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|tskey-[A-Za-z0-9-]{20,})' -- . >/dev/null 2>&1; then
  bad "a secret-shaped string appears in the tree:"
  git grep -nIE '(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|tskey-[A-Za-z0-9-]{20,})' -- . | cut -d: -f1,2 | sed 's/^/    /'
else
  ok "no secret-shaped strings"
fi
if command -v gitleaks >/dev/null 2>&1; then
  if gitleaks detect --source . --no-git --redact --no-banner >/dev/null 2>&1 \
     && { [ ! -d .git ] || gitleaks detect --source . --redact --no-banner >/dev/null 2>&1; }; then
    ok "gitleaks: history and tree clean"
  else bad "gitleaks found secret(s); run: gitleaks detect --source . --redact"; fi
elif [ "${AGENTREACH_GITLEAKS_REQUIRED:-0}" = 1 ]; then
  bad "gitleaks not installed"
fi

#### 4. Core spec #############################################################
say "spec/controls.yaml against control tags"
if ! command -v python3 >/dev/null 2>&1; then
  bad "python3 not on PATH"
elif out=$(python3 ci/spec_check.py 2>&1); then
  ok "$(printf '%s\n' "$out" | tail -1)"
else
  bad "spec and tags disagree:"
  printf '%s\n' "$out" | sed 's/^/    /'
fi

#### 4b. Control coverage ######################################################
say "docs/coverage.md"
if out=$(python3 ci/coverage.py --check 2>&1); then
  ok "$out"
else
  bad "the coverage inventory is stale or missing:"
  printf '%s\n' "$out" | sed 's/^/    /'
fi

#### 5. Fixtures ###############################################################
./ci/fixtures.sh || fail=1

echo
if [ "$fail" -ne 0 ]; then
  printf '\033[31mCHECKS FAILED\033[0m\n'
  exit 1
fi
printf '\033[32mall checks passed\033[0m\n'
