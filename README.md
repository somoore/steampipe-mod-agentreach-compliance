# steampipe-mod-agentreach-compliance

If a malicious instruction reached your coding agent, where could it go?

## What it is

A [Powerpipe](https://powerpipe.io) mod for AI coding agents, built on the [agentreach Steampipe plugin](https://github.com/somoore/steampipe-plugin-agentreach). The plugin discovers every coding agent and harness on the machine automatically (Claude Code, Codex, OpenCode, Cline, Grok Build) and the mod checks what the agent can read, what it obeys, and where it can send data, with one atomic control per fact. The dashboard draws the attack paths as a graph.

No standards body publishes a posture benchmark for coding agents. The closest standard is [OWASP AISVS 1.01](https://github.com/OWASP/AISVS/tree/v1.01/1.01/en), and this mod's **AgentReach assessment profile** is built on it: `spec/controls.yaml` lists the 12 core controls (7 mapped to AISVS, 5 AgentReach extensions), says for each one which AISVS requirement it supplies evidence for (or that it is a AgentReach requirement with no honest AISVS counterpart), what evidence makes it pass, fail or come back not assessed, and what it returns on every test fixture. The other 100 controls are marked `needs_validation` until they earn a record. `docs/audit-2026-10-28.md` is the work list.

Claude Code is the first agent. The name says what it answers: what can the agent reach. Unofficial, not affiliated with Anthropic, OWASP, CIS or AWS.

## Why it exists

Sandboxes, hook guards and MCP scanners each cover one layer. None of them shows the whole picture: which credentials are in reach, which files and servers the agent trusts, and whether the sandbox is even on. This mod is the posture view, modeled on the [lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/): private data × untrusted content × exit channel.

## What it helps with

- Count attack paths on a developer machine and see which single change cuts the most.
- Get a fix sentence for every alarm, naming the vendor's own setting.
- Export results as JSON or CSV for CI or a ticket.

Controls never change anything. No secret value is ever read, stored or shown. Probes open a file for read and discard at most one byte, or dial a port and disconnect.

## What a result means

Read this before trusting a green run.

- **A status is not a proof.** `ok` means a configuration fact or an inert probe supports the control's title; it does not mean the protection held at runtime. Every core control is *supporting* evidence for its AISVS requirement: a verifier still needs runtime evidence (the sandbox actually holding, a prompt actually shown). No control in this mod fully verifies an AISVS requirement on its own.
- **Every fact carries its evidence type** in the plugin's columns: `configured` (read from a settings file), `observed` (an inert probe saw it), `inferred` (derived by agentreach from configured plus observed), or `unknown` (could not be assessed). Modelled reachability is inference from your effective rules; observed mode re-runs the probes inside the sandbox runtime to check it.
- **`skip` is not `ok`.** A control that could not assess what it needed returns `skip` with a reason starting "Not assessed:". Missing evidence never becomes a pass; AG-06 reports the cause.
- **Paths are candidates.** Each leg of a path is established separately, so a path is an attack an agent's configuration permits, not an attack that happened. A declared control on an exit (an egress allowlist, a proxy) makes a path *attested*, not closed: it still counts as a finding.
- **Maturity is per control.** Only the 12 core controls have reviewed records and pinned fixture expectations. The other 100 are tagged `needs_validation`: their verdicts are leads to check, not findings, and `powerpipe benchmark run agentreach` runs both groups (the `agentreach_class` column in JSON or CSV export says which is which).
- **Only Claude Code is assessed.** Every table carries rows for five agents — Claude Code, OpenAI Codex, OpenCode, Cline and Grok Build, discovered automatically — and no control in this mod judges the four that are not Claude Code: a green run says nothing about the other agents installed on the same machine. They are inventory you can query (`select * from agentreach_agent`), not verdicts. `docs/coverage.md` is the generated inventory of which controls have expectations at all.

## Get it running

Install Steampipe and Powerpipe, then the plugin:

```bash
brew install turbot/tap/steampipe turbot/tap/powerpipe
git clone https://github.com/somoore/steampipe-plugin-agentreach
cd steampipe-plugin-agentreach && make install
cp config/agentreach.spc ~/.steampipe/config/agentreach.spc
steampipe service start
```

Clone the mod and run it. Start with the reviewed profile:

```bash
git clone https://github.com/somoore/steampipe-mod-agentreach-compliance
cd steampipe-mod-agentreach-compliance
powerpipe benchmark run core       # the 12 reviewed core controls only
powerpipe benchmark run agentreach # everything: 12 reviewed + 100 still marked needs_validation
powerpipe server                   # dashboard at http://localhost:9033
```

Tell it how the install is governed. Many keys only work in managed settings; a developer who pastes them into `~/.claude/settings.json` gets nothing, and the mod says so instead of passing them:

```bash
powerpipe benchmark run agentreach --var deployment=local        # default: no administrator; managed-only keys skip
powerpipe benchmark run agentreach --var deployment=teams        # Claude for Teams: server-managed settings expected
powerpipe benchmark run agentreach --var deployment=enterprise   # managed-settings.json or MDM expected; user-only protections report info
```

Check the core controls, the regression checks in `test/expectations.yaml`, the whole benchmark (every control must run on every fixture host without an error) and the dashboard against the 19 bundled fixture machines (needs a `agentreach_fixtures` connection; `./ci/fixtures.sh -i` writes it):

```bash
./ci/checks.sh      # parse, tags, agent filter, version wiring, spec, coverage, secrets, fixtures
./ci/fixtures.sh    # only the fixture run; -i installs the agentreach_fixtures connection
```

`./ci/checks.sh` also fails when `docs/coverage.md` — the generated inventory of which controls have expectations — is stale (`python3 ci/coverage.py` regenerates it).

Narrow or tune:

```bash
powerpipe benchmark run lethal_trifecta
powerpipe control run exit_channel_open
powerpipe benchmark run agentreach --var 'require_sandbox=false'
powerpipe benchmark run agentreach --export agentreach.json
```

While the plugin is a local build, every run prints a warning that no plugin satisfies `agentreach@0.2.0`. It is harmless and goes away once the plugin is published.

## The legs

The plugin computes the legs once and exposes them as `agentreach_leg` and `agentreach_path`; every control, card and graph node reads those tables.

- **Untrusted input**: an instruction file a plugin ships, last committed by someone outside the repository's identities, writable by others, or changed since you reviewed it; a project MCP server with no approval decision, or one bundled by an enabled plugin; an enabled plugin hook; web pages the agent fetches, unless WebFetch is denied. Hidden Unicode and HTML comments are reasons to read a file, reported as info, not proof of an attack.
- **Private data**: a file in a sensitive category the agent can open through a shell command or the Read tool. Tier 1 grants access elsewhere (SSH, cloud, secret stores, kubeconfigs), tier 2 is tokens and other agents' state, tier 3 leaks often (.env, shell history, browser profiles).
- **Exit channel**: the internet by shell command (inferred, never probed), allowed domains, WebFetch, MCP servers, plugin hooks and container sockets, each with the approval it needs: `none`, `classifier` (auto mode), or `prompt`. The approval model follows Claude Code's permissions, permission-modes and sandboxing docs, including the sandbox's auto-allow, `strictAllowlist`, the unsandboxed retry and auto mode dropping broad allow rules.
- **Write target**: the agent's settings, instruction files, CI workflows, manifests, git hooks and shell startup files it can change, with the approval each write needs.

A path is a candidate: each leg is established separately. Controls alarm when a path needs no approval at any step and report info when a prompt or the classifier still stands in the way. The dashboard opens with a verdict sentence (or "not fully assessed"), lists the worst concrete paths, draws any one of them step by step, and ranks fixes by how many paths each removes. With a fleet connection, pick the machine at the top of the page.

Without Steampipe, the plugin repository's `agentreach scan` CLI prints the same paths as text, JSON or SARIF, and its skill-only Claude Code plugin (`agentreach-posture`) lets Claude run it for you, check any finding from the CLI or this dashboard against the real configuration, and help fix the confirmed ones.

## Controls

| Group | Controls |
|-------|----------|
| Lethal trifecta (LT) | private data reachable (by tier), credential files not denied, untrusted instruction sources, untrusted MCP servers, exit channel needs approval, exfiltration paths need approval, integrity paths need approval |
| Agent configuration (AG) | sandbox enforced, permission mode allowed, assessment complete, managed settings present, hooks not disabled silently, auto-update decision, no launch flag skips permissions, Agent SDK apps not in bypassPermissions |
| Hooks (HK) | sources owner-writable, sources not git-tracked, timeouts bounded, plugin hooks inventoried, plugin hooks outside the sandbox |
| MCP servers (MCP) | no inline secrets, launchers pinned, project servers explicitly approved, remote servers HTTPS, launcher types allowed |
| Instruction files (IF) | no hidden Unicode, no HTML comments, external includes reviewed, project files tracked, third-party files reviewed |
| Reachability (RC) | sensitive files denied in sandbox, env files not readable, local services restricted, docker socket unreachable, other agents' credentials unreachable, local services as exits |
| Hardening settings (HD) | one control per Claude Code setting a published profile or guide asks for: managed-only locks, bypass and auto mode, every sandbox switch, permission deny and ask rules, MCP allowlists, HTTP hook URLs, login restriction, telemetry, retention, remote control |
| Plugins, marketplaces, skills (SC) | marketplaces inventoried and allowlisted, no auto-update, plugins pinned to a release and owner-writable, plugins with hooks or MCP reviewed, skills inventoried, no external URLs, no hidden content, third-party reviewed |
| CI workflows (CI) | GitHub Actions steps that run Claude Code: no pull request head checked out with the base repository's secrets, the write-access check kept on triggers outsiders can cause, no unrestricted shell on untrusted input, the action pinned to a commit |

### Core profile

| Id | Control | Class | AISVS 1.01 | Evidence |
|----|---------|-------|------------|----------|
| AG-01 | Shell commands run inside an enforced sandbox | mapped | C9.3.1 | supporting |
| AG-02 | Default permission mode keeps a human in the loop | mapped | C9.2.1 | supporting |
| AG-06 | The posture was fully assessed | AgentReach extension | | |
| AG-07 | No launch flag skips permission checks | AgentReach extension | | |
| LT-01 | Sensitive files are not readable by the agent | mapped | AC.3.2 | supporting |
| LT-03 | Instruction files are yours or reviewed | mapped | AC.3.3 | supporting |
| LT-04 | Project MCP servers carry an approval decision | mapped | C10.4.7 | supporting |
| LT-05 | Shell commands cannot reach an unlisted host without approval | AgentReach extension | | |
| LT-06 | No exfiltration path runs without an approval | AgentReach extension | | |
| LT-07 | Untrusted content cannot change guardrails, CI or dependencies without approval | mapped | C9.2.5 | supporting |
| MCP-01 | MCP configuration holds no inline credentials | AgentReach extension | | |
| HK-05 | Plugin hooks that run outside the sandbox are known | mapped | C9.3.1 | supporting |

"Supporting" means the control shows a configuration fact or reachability result the requirement depends on; a verifier still needs runtime evidence. No core control fully verifies an AISVS requirement on its own. AISVS is CC BY-SA 4.0 and is cited here by id only.

## Writing your own controls

The tables are agent-neutral: every row carries an `agent` column, and Codex rows live beside Claude Code rows. A control written for Claude Code must read each table through `(select * from agentreach_x where agent = 'claude_code')`, or it will judge Codex rows by Claude Code rules and mix two agents' posture into one row set. `ci/agent_filter_check.py` enforces this on every SQL block in `controls/` and `dashboards/`. Keep one atomic fact per control, null means unknown, and `skip` when not assessed; add the control's `agentreach` and `agentreach_class` tags. Run `python3 ci/coverage.py` to regenerate `docs/coverage.md` with the new control listed; `ci/checks.sh` fails while it is stale.

## Frameworks

Controls carry tags for the published frameworks they relate to (OWASP Agentic, Skills and MCP Top 10s, MITRE ATLAS, How to Harden, Anthropic's example profiles, Trail of Bits, CSA, CIS, AWS). Those tags are legacy documentation, frozen as they are; AISVS through `spec/controls.yaml` is the one standard the profile is built on. `docs/frameworks.md` lists sources and mapping confidence. Runnable per-framework benchmarks were removed on 2026-10-28 after an audit found them padded, and per-framework views are not re-added until the audit's P and M items are closed (`docs/audit-2026-10-28.md`).

## License

MIT
