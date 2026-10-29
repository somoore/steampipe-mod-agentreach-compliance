#!/usr/bin/env bash
# Behavioural check against the fixture snapshots in test/snapshots: each
# core control in spec/controls.yaml and each regression check in
# test/expectations.yaml must return the expected status per host, the whole
# benchmark must run without an error row on any host (the net under the
# replace()-built hardening SQL), and the dashboard must render for every
# host as test/dashboard.yaml says.
#
#   ./ci/fixtures.sh            run the controls
#   ./ci/fixtures.sh -r         first regenerate the snapshots from the plugin
#                               repo checked out next to this one, and fail if
#                               they differ from the committed ones
#   ./ci/fixtures.sh -i [-r]    also write the agentreach_fixtures connection to
#                               ~/.steampipe/config/agentreach_fixtures.spc (from
#                               test/agentreach_fixtures.spc.example) and restart
#                               the steampipe service; CI uses this
#
# Needs steampipe with the agentreach plugin (v0.2.0 or newer), a running
# steampipe service, powerpipe and python3 with PyYAML, plus a connection
# named agentreach_fixtures:
#
#   connection "agentreach_fixtures" {
#     plugin         = "local/agentreach"
#     snapshot_paths = ["<this repo>/test/snapshots/*.json"]
#   }
#
# Without them it prints why and exits 0, unless AGENTREACH_FIXTURES_REQUIRED=1.
# Without -i nothing here writes outside the repository except -r's
# temporary directory.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 1
conn=${AGENTREACH_FIXTURES_CONNECTION:-agentreach_fixtures}

skip() {
  printf '\033[33m  skipped: %s\033[0m\n' "$1"
  [ "${AGENTREACH_FIXTURES_REQUIRED:-0}" = 1 ] && exit 1
  exit 0
}

printf '\n\033[1m== core controls against fixtures\033[0m\n'
for t in steampipe powerpipe python3; do
  command -v "$t" >/dev/null 2>&1 || skip "$t is not on PATH"
done
python3 -c 'import yaml' 2>/dev/null || skip "PyYAML is missing (pip install pyyaml)"

install=0; regen=0
for a in "$@"; do
  case "$a" in -i) install=1 ;; -r) regen=1 ;; *) echo "usage: $0 [-i] [-r]"; exit 2 ;; esac
done

if [ $install = 1 ]; then
  dir=${STEAMPIPE_INSTALL_DIR:-$HOME/.steampipe}/config
  mkdir -p "$dir"
  sed "s|@REPO@|$(pwd)|" test/agentreach_fixtures.spc.example > "$dir/agentreach_fixtures.spc"
  echo "  ok: wrote $dir/agentreach_fixtures.spc"
  # Powerpipe needs the service, not a one-off steampipe query.
  if steampipe service status 2>/dev/null | grep -q "Steampipe service is running"; then
    steampipe service restart >/dev/null
  else
    steampipe service start >/dev/null
  fi
  steampipe service status | grep -q "Steampipe service is running" \
    || { echo "  FAIL: the steampipe service did not start"; steampipe service status; exit 1; }
  echo "  ok: steampipe service running"
fi

if [ $regen = 1 ]; then
  plugin="$(cd .. && pwd)/steampipe-plugin-agentreach"
  [ -d "$plugin/cmd/agentreach-fixtures" ] || { echo "  FAIL: -r needs $plugin"; exit 1; }
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  (cd "$plugin" && go run ./cmd/agentreach-fixtures -out "$tmp") >/dev/null || { echo "  FAIL: agentreach-fixtures did not run"; exit 1; }
  if ! diff -r "$tmp" test/snapshots >/dev/null; then
    echo "  FAIL: test/snapshots is stale. Regenerate with:"
    echo "        (cd $plugin && go run ./cmd/agentreach-fixtures -out $(pwd)/test/snapshots) && steampipe service restart"
    diff -rq "$tmp" test/snapshots | sed 's/^/        /'
    exit 1
  fi
  echo "  ok: snapshots match the plugin's generator"
fi

steampipe query "select 1 from ${conn}.agentreach_agent limit 1" >/dev/null 2>&1 \
  || skip "no '${conn}' connection, or the service is not running (see the header of this script)"
missing=$(steampipe query "select count(*) from ${conn}.agentreach_path where approval is null" --output csv 2>&1 | tail -1)
case "$missing" in
  0|[1-9]*) : ;;
  *) skip "the installed agentreach plugin predates agentreach_path.approval; rebuild it (make install) and restart the service" ;;
esac

rc=0
python3 ci/fixtures_check.py "$conn" || rc=1
python3 ci/benchmark_check.py "$conn" || rc=1
python3 ci/dashboard_check.py "$conn" || rc=1
exit $rc
