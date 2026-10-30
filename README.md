# steampipe-mod-agentreach-compliance

If a malicious instruction reached your coding agent, where could it go?

A [Powerpipe](https://powerpipe.io) mod built on the [agentreach plugin](https://github.com/somoore/steampipe-plugin-agentreach). It checks what the agent can read, what it obeys, and where it can send data. Every verdict is deterministic, and the dashboard draws the attack paths as a graph.

The plugin discovers five agents automatically (Claude Code, Codex, OpenCode, Cline and Grok Build). Only Claude Code is judged here. The other four appear as inventory rows so you can query them, and the dashboard opens with a table of what is installed.

## Run it

Install Steampipe, Powerpipe and the agentreach plugin first (the plugin README has the steps). Then:

```bash
powerpipe benchmark run core        # the 12 core controls
powerpipe benchmark run agentreach  # everything
powerpipe server                    # dashboard at http://localhost:9033
```

While the plugin is a local build, every run prints a warning that nothing satisfies `agentreach@0.2.0`. It is harmless and goes away once the plugin is published.

Tell the mod how the install is governed, because many settings only work at managed scope:

```bash
powerpipe benchmark run agentreach --var deployment=local      # no administrator
powerpipe benchmark run agentreach --var deployment=teams      # server-managed settings expected
powerpipe benchmark run agentreach --var deployment=enterprise
```

## What it checks

No standards body publishes a posture benchmark for coding agents yet, so the core profile is built on [OWASP AISVS 1.01](https://github.com/OWASP/AISVS/tree/v1.01/1.01/en). `spec/controls.yaml` lists the 12 core controls (7 mapped to AISVS, 5 agentreach extensions) and the evidence that makes each one pass, fail or come back not assessed. The other 100 controls are marked `needs_validation` until they earn the same record.

The groups: lethal trifecta, agent configuration, hooks, MCP servers, instruction files, reachability, hardening settings, plugins and skills, and the CI workflows that run the agent.

## Read a result before trusting it

- `ok` means a configuration fact or an inert probe supports the claim. It is not runtime proof.
- `skip` is not `ok`. It means the control could not assess what it needed, and missing evidence never becomes a pass.
- Attack paths are candidates. Each leg is established separately, and nothing was attacked.
- Export to JSON or CSV and the `agentreach_class` column tells you which verdicts are reviewed and which are still leads.

## Development

`./ci/checks.sh` runs everything: parse, tags, the agent filter, version wiring, secrets, the spec and coverage, then the controls and the dashboard against the 19 bundled fixture machines (needs Powerpipe; the fixture section also needs Steampipe and the plugin). `./ci/checks.sh --quick` skips the fixtures, which is what the pre-commit hook runs. CI runs them before merge, and CI skips them for markdown-only changes. `docs/coverage.md` is the generated inventory of which controls have expectations. CONTRIBUTING.md has the recipe for adding a control, and SECURITY.md covers reporting.

## License

MIT
