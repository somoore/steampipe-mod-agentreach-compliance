# Contributing

The mod is deterministic posture checks: controls never fix anything, no
secret value is ever selected or displayed, and a machine with no coding
agent installed is a clean result. If your change breaks any of those, it
will not merge.

## The short version

1. Fork, branch, PR. `main` requires the CI checks to pass; the repository
   owner reviews everything (CODEOWNERS).
2. `./ci/checks.sh` must pass locally before you push. It needs powerpipe
   on PATH; the fixture section also needs Steampipe with the
   [agentreach plugin](https://github.com/somoore/steampipe-plugin-agentreach)
   installed (`make install` there) and a `agentreach_fixtures` connection
   (`./ci/fixtures.sh -i` writes it).
3. The rules that do not change: one atomic control per fact, null means
   unknown, `skip` when not assessed, controls never fix anything, no
   secret value is ever selected or displayed, and every query filters
   `agent = 'claude_code'` (the CI agent-filter check enforces the last).
4. A security issue is never a public issue or PR: use
   **Security → Report a vulnerability** (see SECURITY.md).

## Adding a control

The plugin column that proves the condition comes first - never approximate
a missing column in SQL; change the plugin. Then the control in the matching
`controls/*.pp` group with `agentreach` and
`agentreach_class = "needs_validation"` tags, a fixture scenario in the
plugin's `cmd/agentreach-fixtures` for every branch the fixtures miss,
fixture expectations, and `python3 ci/coverage.py` to regenerate the
coverage inventory. Controls join the core profile only with a
`spec/controls.yaml` record and fixture expectations on every host.
