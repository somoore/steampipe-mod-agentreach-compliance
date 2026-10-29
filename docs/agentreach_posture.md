## What this page answers

**Could content I did not write make my coding agent read a secret and send it somewhere?** The verdict at the top is generated from the data on this machine and names the secrets at risk.

## How to read it

- **Worst attack paths**: one row per private file, with the worst untrusted source that could reach it, what the agent would run, where the data would leave, what blocks it today, and the one-line fix. Rows are ranked by blast radius (tier 1 first).
- **Follow one path**: pick a row from the dropdown and the graph draws it as four steps: the untrusted source, Claude Code, the file it reads, where the data leaves. Red labels on the edges are the controls that would have stopped that step. The table underneath says the same thing in plain words, with the state of each control.
- **What to change first**: fixes ranked by how many paths each closes, with the exact `settings.json` snippet.
- The detail tables list every reachable private file, every MCP server with a finding, and every hook that runs outside the sandbox.
- **Frameworks** (link at the bottom) opens one page per published framework, each embedding that benchmark's status tree over the same controls.

## Definitions

An **untrusted source** is a skill, command, subagent or instruction file that a plugin ships or that was last changed by someone else or carries hidden text; a project MCP server with no approval decision; or an enabled plugin hook. **Private files** are the catalogued credential and secret paths the agent can open. **Exits** are the internet (assumed open, never probed), reachable local services, and plugin hooks. Nothing on this page probes a secret's contents or sends anything anywhere.
