# steampipe-mod-agentreach-compliance

If a malicious instruction reached your coding agent, where could it go?

## What it is

A [Powerpipe](https://powerpipe.io) mod built on the [agentreach plugin](https://github.com/somoore/steampipe-plugin-agentreach). It checks what the agent can read, what it obeys, and where it can send data. One control per fact, every verdict deterministic, and the dashboard draws the attack paths as a graph.

The plugin discovers five agents automatically (Claude Code, Codex, OpenCode, Cline and Grok Build). Only Claude Code is judged here; the other four appear as inventory rows so you can query them, and the dashboard opens with a table of what is installed.

No standards body publishes a posture benchmark for coding agents yet, so the core profile is built on [OWASP AISVS 1.01](https://github.com/OWASP/AISVS/tree/v1.01/1.01/en). `spec/controls.yaml` lists the 12 core controls (7 mapped to AISVS, 5 agentreach extensions) and the evidence that makes each one pass, fail or come back not assessed. The other 100 controls are marked `needs_validation` until they earn the same record.

## Read a result before trusting it

- `ok` means a configuration fact or an inert probe supports the claim. It is not runtime proof.
- `skip` is not `ok`. It means the control could not assess what it needed, and missing evidence never becomes a pass.
- Attack paths are candidates. Each leg is established separately, and nothing was attacked.
- Export to JSON or CSV and the `agentreach_class` column tells you which verdicts are reviewed and which are still leads.

## Run it

Install Steampipe and Powerpipe, then the [agentreach plugin](https://github.com/somoore/steampipe-plugin-agentreach) (its README has the steps). Then:

```bash
powerpipe benchmark run core        # the 12 reviewed controls
powerpipe benchmark run agentreach  # everything: 112 controls
powerpipe server                    # dashboard at http://localhost:9033
```

Tell the mod how the install is governed, because many settings only work at managed scope:

```bash
powerpipe benchmark run agentreach --var deployment=local      # no administrator
powerpipe benchmark run agentreach --var deployment=teams     # server-managed settings expected
powerpipe benchmark run agentreach --var deployment=enterprise
```

## The controls

Nine groups: lethal trifecta (the private data, untrusted input and exit channel model), agent configuration, hooks, MCP servers, instruction files, reachability, one control per hardening setting, plugins and skills, and the CI workflows that run the agent. The reviewed core profile:

| Id | Control | AISVS 1.01 | Evidence |
|----|---------|------------|----------|
| AG-01 | Shell commands run inside an enforced sandbox | C9.3.1 | supporting |
| AG-02 | Default permission mode keeps a human in the loop | C9.2.1 | supporting |
| AG-06 | The posture was fully assessed | agentreach extension | |
| AG-07 | No launch flag skips permission checks | agentreach extension | |
| LT-01 | Sensitive files are not readable by the agent | AC.3.2 | supporting |
| LT-03 | Instruction files are yours or reviewed | AC.3.3 | supporting |
| LT-04 | Project MCP servers carry an approval decision | C10.4.7 | supporting |
| LT-05 | Shell commands cannot reach an unlisted host without approval | agentreach extension | |
| LT-06 | No exfiltration path runs without an approval | agentreach extension | |
| LT-07 | Untrusted content cannot change guardrails, CI or dependencies | C9.2.5 | supporting |
| MCP-01 | MCP configuration holds no inline credentials | agentreach extension | |
| HK-05 | Plugin hooks that run outside the sandbox are known | C9.3.1 | supporting |

"Supporting" means the control shows a configuration fact or reachability result the requirement depends on; a verifier still needs runtime evidence. AISVS is CC BY-SA 4.0 and is cited by id only. Framework tags on the other controls are legacy documentation, frozen as they are; `docs/frameworks.md` lists sources.

## Development

`./ci/checks.sh` runs everything: parse, tags, the agent filter, version wiring, secrets, the spec and coverage, then the fixtures against the 19 bundled fixture machines (needs Powerpipe; the fixture section also needs Steampipe and the plugin). `./ci/checks.sh --quick` skips the fixtures, which is what the pre-commit hook runs; CI runs them before merge, and CI skips them for markdown-only changes. `docs/coverage.md` is the generated inventory of which controls have expectations. CONTRIBUTING.md has the recipe for adding a control; SECURITY.md covers reporting.

While the plugin is a local build, every run prints a warning that nothing satisfies `agentreach@0.2.0`. It is harmless and goes away once the plugin is published.

## License

MIT
