# Security findings — steampipe-mod-agentreach-compliance

- **Scanned:** 2026-11-02, commit `b19aeda` (working tree clean at baseline), 62 tracked files.
- **Target:** a read-only Powerpipe/Steampipe mod (HCL controls + dashboards) plus local CI scripts. No service, listener, stored credential, or untrusted runtime input.
- **Tools:** semgrep, bandit, trivy (repo/config), gitleaks (worktree + history), shellcheck; local `powerpipe` 1.5.2 / `steampipe` 2.4.4 against the committed fixture snapshots.
- **Team roles:** PM, AppSec, Pentester, Devil's Advocate, QA. The Devil's Advocate wins on verdicts, the Pentester on reachability.
- **Verification entry points:** `./ci/checks.sh`, `./ci/fixtures.sh`, `gitleaks detect`, `shellcheck`, `actionlint`.

`FIXED` is only claimed where the listed command was run and passed on this tree. This repo's only third-party Python
dependency is PyYAML; there is no build step.

## Findings

| ID | Severity | Status | Location | Issue | Fix | Verification |
|----|----------|--------|----------|-------|-----|--------------|
| **SEC-01** | HIGH | **FIXED** | `controls/reach.pp:50,91,221`; `controls/trifecta.pp:147`; `controls/supply_chain.pp:215` | Five controls joined `agentreach_agent` on `a.agent = f.agent` only. Under a fleet connection (the documented 19-snapshot fixture setup) each file row was repeated once per host and graded with another machine's `sandbox_enabled`; RC-01/RC-02/RC-05/LT-02 did not even select `host`, and SC-09 multiplied skill counts 19×. Violated the guarantee in `controls/assessment.pp:5-7`. | Join `(host, snapshot_id, agent)` via `local.same_snapshot_sql`; add `a.host` to RC-01/RC-02/RC-05/LT-02's columns; group SC-09 by host/snapshot and label its resource with the host. | `powerpipe control run credential_files_not_denied --search-path-prefix agentreach_fixtures --output csv`: 893 → 47 rows, 19 hosts, 0 duplicate `(host, resource)`, 0 conflicting `ok`+`alarm`; RC-01 760 → 40; whole benchmark 3986 → 1921 rows, 0 errors. Static regression rule added: `python3 ci/agent_filter_check.py` (green; a scratch `on a.agent = f.agent` mutation exits 1). `./ci/fixtures.sh` green. |
| **SEC-02** | LOW | **FIXED** | `dashboards/posture.pp:732,733,743,759,776,786,795` | The dashboard's "Snippet" column (JSON the user is told to paste into `settings.json`) was built by string concatenation of plugin titles and file paths. A `"` or `\` in either produced invalid JSON or injected extra keys; the MCP row also emitted two top-level objects joined by a comma, which is not valid JSON. | Build every snippet with `jsonb_build_object`/`jsonb_object_agg`/`jsonb_agg`/`jsonb_strip_nulls` and cast to text, so PostgreSQL escapes quotes and backslashes. Column order and titles unchanged. | `ci/dashboard_check.py` now parses every non-empty `Snippet` cell on all 19 hosts (38 panels each): green. Ad-hoc `jsonb_object_agg` probe with title `p"x\y@m` returns escaped, parseable JSON. A fake panel with malformed JSON makes the new check exit 1. |
| **SEC-03** | LOW | **FIXED** | `ci/benchmark_check.py:46-55` | `set(csv.DictReader(...))` always raised `TypeError: unhashable type: 'dict'`; the broad `except Exception: pass` swallowed it. Additionally `powerpipe control list --output csv` prints nothing, so the "every listed control returned rows" check had never executed. | Parse `powerpipe control list --output json`, normalise `qualified_name` to `control.<name>`, fail on a non-zero listing exit, and narrow the exception to `ValueError`/`KeyError`/`TypeError`. | `python3 ci/benchmark_check.py agentreach_fixtures` → `112 controls, 1921 rows, 0 errors`, rc 0. A fake `powerpipe` listing one extra `control.ghost_control` → `FAIL ... returned no rows`, rc 1. |
| **SEC-04 / D-03** | LOW | **FIXED** | `.github/dependabot.yml:3` | No `cooldown`: a freshly published or compromised action version could be proposed and merged immediately (SHA pinning fixes the ref, not the release content). | Added `cooldown: default-days: 7` to the `github-actions` updater (grouping retained). Security updates are exempt from cooldown. | `python3 -c "import yaml; d=yaml.safe_load(open('.github/dependabot.yml')); assert d['updates'][0]['cooldown']['default-days'] >= 7"` passes; `actionlint` rc 0. |
| **PT-01 / D-14** | LOW | **FIXED** | `.github/workflows/ci.yml:50,122` | PyYAML was version-pinned but not hash-pinned; a compromised index or TLS-terminating mirror could deliver different bytes that execute during `pip install` in both jobs. | Added `requirements-ci.txt` (`pyyaml==6.0.3` with the SHA-256 of every published artifact) and both jobs now run `pip install --user --require-hashes -r requirements-ci.txt`. Added a `pip` ecosystem to Dependabot so the hashes are refreshed. Also added missing `timeout-minutes` (D-13). | `python3 -m pip install --require-hashes -r requirements-ci.txt` in a Python 3.14 venv installs 6.0.3. `pip download --require-hashes --only-binary=:all: --platform manylinux2014_x86_64 --python-version 3.12 -r requirements-ci.txt` selects the cp312 manylinux wheel; tampering that wheel's hash makes pip exit 1 (`THESE PACKAGES DO NOT MATCH THE HASHES`). `./ci/checks.sh` green with 6.0.3. |
| **PT-02 / QA-08** | LOW | **FIXED** | `ci/fixtures.sh:55` (now 62) | `sed "s\|@REPO@\|$(pwd)\|"` did not escape `&`, `\|` or newlines in the checkout path, so an odd directory name could corrupt or extend the generated HCL. | Replaced `sed` with a three-line `python3` literal `str.replace`; a non-zero write fails the script. | `STEAMPIPE_INSTALL_DIR=<tmp> ./ci/fixtures.sh -i` with a fake `steampipe`: exactly one `@REPO@`-free connection file written; `grep -c '@REPO@'` = 0; `shellcheck` rc 0. |
| **D-13** | LOW | **FIXED** | `.github/workflows/ci.yml` | No `timeout-minutes` on any job; a hung `powerpipe`/`steampipe` call could pin a runner for 360 minutes. | `validate: 15`, `fixtures: 30`, `dependency-review: 10` (generous vs. the observed 17 s / ~4 min runs). | `actionlint` rc 0; full local suite well under the limits. |
| **D-15** | INFO | **MITIGATED** | `ci/fixtures.sh:52-63` | `-i` unconditionally overwrote `~/.steampipe/config/agentreach_fixtures.spc`; a hand-written connection was lost. | Before overwriting, copy an existing file to `agentreach_fixtures.spc.bak` and say so. `-i` is still an explicit opt-in that replaces the file. | `STEAMPIPE_INSTALL_DIR=<tmp> ./ci/fixtures.sh -i` wrote the new file and preserved the old contents in `.bak`. Residual: the overwrite itself is by design. |
| **QA-01** | HIGH (test gap) | **MITIGATED** | `ci/agent_filter_check.py:28,40` | The agent-filter guard was a substring test over the raw heredoc, so `-- a.agent = 'claude_code'` satisfied it; a second unfiltered reference in the same block also passed. | Strip SQL comments before matching (comment-only filters now fail), and added the SEC-01 join rule. Per-reference filtering (every read inside its own filtered CTE) is not checked. | `python3 ci/agent_filter_check.py` green; the comment-only mutation exits 1 (new); the SEC-01 join mutation exits 1 (new). Residual: QA-01's "second unfiltered reference" mutation can still pass the static check. |
| **QA-06** | LOW (test gap) | **MITIGATED** | `.github/workflows/ci.yml` | `shellcheck`, `bash -n`, `py_compile` and `actionlint` were not run in CI although all passed locally. | Added a `validate` step for `bash -n`, `python3 -m py_compile ci/*.py` and `shellcheck` on the three shell scripts. `actionlint` is not preinstalled on `ubuntu-latest`, so it stays a local check. | `shellcheck ci/checks.sh ci/fixtures.sh ci/hooks/pre-commit` rc 0; `bash -n` rc 0; `py_compile` rc 0; `actionlint .github/workflows/ci.yml` rc 0 locally. |
| **D-01** | INFO | **FALSE POSITIVE** | `ci/fixtures_check.py:38` | semgrep's `dangerous-subprocess-use-tainted-env-args`: the call is list-argv, `shell=False`; `conn` is a value slot and `--var` values come from repo YAML. Reaching it requires already running code. | None (the suggested `shlex.quote` would corrupt a non-shell argv). | Code inspection. |
| **D-02** | INFO | **FALSE POSITIVE** | `ci/dashboard_check.py:55` | bandit B608: `"select count(*) from %s.agentreach_agent" % conn` is a cache warm-up on the local CLI; `conn` is an operator/CI-chosen connection name, not user data. Fixing it with `shlex.quote`/an over-strict regex would break legal names. | None; documented as a local dev-script identifier interpolation, not SQL injection. | Code inspection; the query only warms the fixture connection. |
| **D-04** | INFO | **FALSE POSITIVE** | `ci/*.py:16,14,20` | bandit B404 (subprocess import) is informational; all uses are fixed-argv, `shell=False`. | None. | Code inspection. |
| **D-05** | INFO | **FALSE POSITIVE** | `ci/benchmark_check.py:21,46`; `ci/dashboard_check.py:32,54`; `ci/fixtures_check.py:38` | bandit B603: no untrusted input reaches any argv; executables are literals. | None. | Code inspection. |
| **D-06** | INFO | **FALSE POSITIVE** | `ci/benchmark_check.py:21,46`; `ci/dashboard_check.py:54` | bandit B607 (partial path): "tools on PATH" is the documented contract (`fixtures.sh:42-44`, `checks.sh:37`); PATH hijack implies control of the runner already. | None; an absolute path would break venv/local installs. | Code inspection. |
| **D-07** | INFO | **FALSE POSITIVE** | `ci/benchmark_check.py:54` | bandit B110: the broad `except` guarded only a secondary listing opinion; the primary assertions had already run. The real consequence (dead check) is fixed as SEC-03. | None beyond SEC-03. | Code inspection. |
| **D-08** | INFO | **FALSE POSITIVE** | `trivy.json`, `trivy-config.json` | Empty trivy results mean "no lockfile/container/IaC manifest to scan", not a clean bill for HCL/Python. | None; trivy is out of scope for this repo. | Report inspection. |
| **D-09** | INFO | **FALSE POSITIVE** | worktree/history | gitleaks (tree + 38-commit history) and shellcheck are empty. `test/agentreach_fixtures.spc.example` is a tracked example with `snapshot_paths` only. | None. | `gitleaks detect --source . --redact --no-banner` and `--no-git` clean; `AGENTREACH_GITLEAKS_REQUIRED=1 ./ci/checks.sh` green. |
| **D-10** | INFO | **FALSE POSITIVE** | `controls/hardening.pp` | `__KEY__/__COND__/__FIX__/__ABSENT_REASON__` are replaced with constants from the same `.pp`; user values flow through typed `param` bindings. Editing the `.pp` already means running SQL. | None. | Code inspection; `ci/checks.sh` template-hygiene checks green. |
| **D-11** | INFO | **FALSE POSITIVE** | `ci/fixtures_check.py:36`; `ci/dashboard_check.py:31` | `--var k=v` values come from repo YAML and each is one argv element; a value cannot become a new flag. | None. | Code inspection. |
| **D-12** | INFO | **FALSE POSITIVE** | `ci/fixtures.sh:55` | The `sed` path-substitution risk was real but local/operator-only; it is fixed under PT-02/QA-08 rather than treated as an injection vulnerability. | See PT-02. | See PT-02. |
| **D-16** | LOW | **ACCEPTED RISK** | `test/expectations.yaml`, `test/snapshots/*` | Fixture expectations and snapshots live in the same PR as the controls they judge, so a PR can weaken its own oracle. A wrong control produces a wrong report, not a compromise. | Mitigated by CODEOWNERS requiring two identities and review; a change-coupling CI heuristic would misfire on legitimate refactors. | `CODEOWNERS` inspection; `./ci/fixtures.sh -r` (CI) keeps the committed oracle equal to the plugin generator. |
| **QA-02** | MEDIUM (test gap) | **DEFERRED** | `ci/dashboard_check.py:93-101,141-160`; `controls/legs.pp:16` | Cross-host leak detection is a `/home/fx-*` regex blinded by `tilde_sql`, and isolation is asserted for one host only. | Not fixed here (needs per-panel comparison on a second host); the dashboard queries themselves filter `host`. | Existing isolation check green for `fx-open` against `agentreach_fixtures_one`. Residual risk below. |
| **QA-03** | MEDIUM (test gap) | **DEFERRED** | `ci/*.py`, `ci/checks.sh` | No unit tests for the six CI checkers; structural checks are regex/awk heuristics. | Out of scope for this pass. Negative evidence for the two changed checkers is recorded above (mutation runs). | `./ci/checks.sh` green; mutation runs exit 1 as recorded. |
| **QA-04** | MEDIUM (test gap) | **DEFERRED** | `ci/checks.sh:99-101` | The apostrophe check covers `controls/*.pp` only; dashboards are not covered. | No dashboard or leg template currently uses `__FIX__`/`__ABSENT_REASON__` (`grep` empty), so there is nothing to escape today. | `grep -nE '"__(FIX\|ABSENT_REASON)__", "[^"]*'"'"'' dashboards/*.pp` empty. |
| **QA-05** | LOW (test gap) | **DEFERRED** | repo-wide | Every gate asserts success; there is no committed mutation harness proving a gate still fails. | Not added (needs Steampipe and a scratch clone; belongs in a scheduled job). | Mutation evidence in this file is manual. |
| **QA-07** | LOW | **DEFERRED** | GitHub branch protection | `required_signatures: false`, `require_last_push_approval: false`. | Repository settings, not files; the fixer cannot set them. Owner decision. | Cannot be verified from the repo; recorded as residual risk. |
| **QA-09** | INFO | **ACCEPTED RISK** | toolchain | Local tool versions differ from CI pins (powerpipe 1.5.2/steampipe 2.4.4 vs 1.5.6/2.4.8), so local green ≠ CI. | CI is the authority and was green (8/8 runs on `main` at baseline); documented rather than pinned. | `powerpipe --version`, `steampipe --version`; CI history. |

## Verification commands and results

```
# Bash/Python gates (PyYAML 6.0.3 from requirements-ci.txt on PATH)
shellcheck ci/checks.sh ci/fixtures.sh ci/hooks/pre-commit   # rc 0
bash -n ci/checks.sh ci/fixtures.sh ci/hooks/pre-commit      # rc 0
python3 -m py_compile ci/*.py                                # rc 0
actionlint .github/workflows/ci.yml                          # rc 0

# Full repository gate (includes gitleaks history + worktree, spec, coverage)
AGENTREACH_GITLEAKS_REQUIRED=1 ./ci/checks.sh                # all checks passed
AGENTREACH_FIXTURES_REQUIRED=1 ./ci/fixtures.sh              # rc 0: 112 controls, 1921 rows, 0 errors;
                                                             # 19 dashboards x 38 panels, isolation ok

# Regressions for the fixed classes
python3 ci/agent_filter_check.py                             # pass; join mutation and comment-only
                                                             # filter mutation each exit 1
python3 ci/benchmark_check.py agentreach_fixtures             # pass; extra listed control exits 1
python3 ci/dashboard_check.py agentreach_fixtures             # pass; malformed Snippet exits 1

# Supply-chain pin
pip download --require-hashes --only-binary=:all: \
  --platform manylinux2014_x86_64 --python-version 3.12 \
  -r requirements-ci.txt                                     # cp312 manylinux wheel selected
# tampered wheel hash -> rc 1 (THESE PACKAGES DO NOT MATCH THE HASHES)
```

## Residual risk

- **QA-02:** dashboard cross-host isolation is proven for one host and the leak regex cannot see `~`-rewritten paths. A
  future panel that drops `host = (select host from scope)` could still pass. Compensating control: every panel's
  underlying query was reviewed and does filter `host`; `scope_sql` mutation (ignoring `$1`) is caught.
- **QA-03/QA-05:** the CI checkers still have no unit tests and there is no committed mutation harness. The negative
  tests for the three fixes in this pass were run manually and are recorded above.
- **QA-01 (residual):** a block with a correctly filtered reference *and* a second unfiltered read still passes the
  static filter check; only controls with fixture expectations catch it behaviourally.
- **D-16:** tests and fixtures ship in the same PR as the controls they judge; review and CODEOWNERS are the control.
- **QA-07:** commit signatures and last-push approval are repository settings; they remain disabled unless the owner
  enables them.
- **PT-01:** PyYAML is 6.0.3 (patch bump from the 6.0.2 the audit saw) so hash-pinned wheels exist for Python 3.14;
  a Python 3.15 runner would fall back to the sdist hash and may need a newer PyYAML. Dependabot (pip) now refreshes
  the pins. `--require-hashes` was validated for cp312 manylinux and cp314 macOS, not on the GitHub runner itself.
- **D-15:** `./ci/fixtures.sh -i` still replaces `~/.steampipe/config/agentreach_fixtures.spc`; it now keeps a `.bak`.
- No secret was found in the tree or history, so no rotation is required. No git history was rewritten and nothing was
  committed.
