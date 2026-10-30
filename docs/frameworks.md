> Status 2026-10-28: the runnable per-framework benchmarks described below were moved to the `frameworks-archive` branch. On `main` the framework keys are tags only. Read the commit history before restoring any of them.
>
> The AgentReach assessment profile now has one primary standard, OWASP AISVS 1.01, recorded in `spec/controls.yaml` with tags `agentreach_class` and `aisvs`. Every tag key described on this page is legacy: frozen, not added to new controls. The CIS AI Agents Companion Guide v1.0 (2026-04-20) is published and is secondary guidance, cited by Safeguard number; the CIS MCP Server Benchmark v1.0.0 (2026-09-16) sits behind a registration form and has not been reviewed.

# Framework mappings

Every framework in this mod is a benchmark in `controls/frameworks/` that regroups the atomic controls in `controls/*.pp` under the source's own headings. Tags on the controls are the index; the benchmarks are the runnable view.

```bash
powerpipe benchmark list
powerpipe benchmark run anthropic_profile_strict
powerpipe benchmark run howtoharden_l2
powerpipe benchmark run owasp_agentic --var deployment=enterprise
```

## What exists, and what does not

Surveyed 2026-10-27. No standards body publishes a posture benchmark for AI coding agents: there is no CIS benchmark, no NIST profile and no ISO document. (The 2026-10-27 survey found the CIS AI agents companion guide URL dead; the guide itself was found on 2026-10-28, see the status note above.) Everything below is vendor documentation, a community guide, or a risk list that had to be mapped to settings by hand. Where a title or number could only be confirmed from a secondary source, the benchmark description and this page say so.

The spine of the mod is not a framework but a model: Simon Willison's **lethal trifecta**. An agent that (1) can read private data, (2) is exposed to content an attacker can influence, and (3) has a way to send data out, can be made to exfiltrate. Every framework below describes one or more legs of that triangle in its own vocabulary.

## The deployment tier

`var.deployment` (`local`, `teams`, `enterprise`) changes what a settings control accepts, because Anthropic's settings reference marks some keys **managed-only**: Claude Code ignores them unless they come from `managed-settings.json`, an MDM profile, or the server-managed policy that Team and Enterprise admins push from the claude.ai console (cached at `~/.claude/remote-settings.json`, which the plugin reads at managed scope).

| Situation | local | teams | enterprise |
|-----------|-------|-------|------------|
| Managed-only key set at managed scope | ok | ok | ok |
| Managed-only key found in user or project settings | alarm (ignored there) | alarm | alarm |
| Managed-only key absent | skip | alarm | alarm |
| Any-scope key set at user scope | ok | ok | info (a project file can override it) |
| Any-scope key set at user scope but weakened by a project or local file | alarm | alarm | alarm |
| Manual item that only exists for organizations | skip | info | info |

## Tag keys

| Tag | Framework | Value format |
|-----|-----------|--------------|
| `agentreach` | This mod's own control id | `LT-01`, `HD-13`, `SC-05` |
| `agentreach_class` | Profile class: `mapped`, `agentreach_extension`, `needs_validation` | `mapped` |
| `aisvs` | OWASP AISVS 1.01 requirement ids, on `mapped` controls only | `v1.01-C9.2.5` |
| `owasp_agentic` | OWASP Top 10 for Agentic Applications 2026 | `ASI03` (older controls: `ASI03 Identity and Privilege Abuse`) |
| `owasp_skills` | OWASP Agentic Skills Top 10 v1.0-2026 | `AST05` |
| `owasp_mcp` | OWASP MCP Top 10 v0.1 | `MCP09` |
| `owasp_llm_2025` | OWASP Top 10 for LLM Applications 2025 | `LLM01:2025 Prompt Injection` |
| `mitre_atlas` | MITRE ATLAS technique or mitigation | `AML.T0086`, `AML.M0029` |
| `hth` | How to Harden Claude Code guide control | `3.1` |
| `nist_800_53` | NIST SP 800-53 control (as cited by How to Harden) | `SC-7` |
| `anthropic_profile` | Anthropic example profiles that set the key | `strict,bash_sandbox,hipaa` |
| `trailofbits` | Section of the Trail of Bits settings.json | `deny`, `env`, `hooks`, `mcp` |
| `csa_mcp` | CSA MCP best-practices domain or maturity level | `3.5`, `L1` |
| `ciso_guide` | Anthropic CISO guide control requirement | `1` to `7` |
| `cis_controls_v8` | CIS Controls v8.1 safeguard | `3.3` |
| `aws_coding_agent_framework` | AWS control framework for AI coding agents | `R001` or a control theme |
| `owasp_agent_cheatsheet`, `knostic_threat_model` | Legacy keys kept on the original 32 controls | section numbers |
| `type` | `manual` marks a framework item a reviewer must answer | `manual` |

## Sources

### Anthropic example settings profiles (`anthropic_profiles`)

URL: https://github.com/anthropics/claude-code/tree/main/examples/settings (lax, strict, bash-sandbox, hipaa). The README calls them community-maintained snippets, so they are a baseline, not policy. Confidence: **exact**; each profile benchmark contains the controls for the keys the file sets. The strict profile is the de facto baseline: bypass mode disabled, Bash on ask, WebFetch and WebSearch denied, managed-only permission rules and hooks, empty marketplace allowlist, empty sandbox network allowlist. The HIPAA pair adds login restriction, provider allowlist, credential hiding, OpenTelemetry with content logging off, and 30-day retention.

### How to Harden: Claude Code Hardening Guide (`howtoharden_claude_code`, `howtoharden_l1/l2/l3`)

URL: https://howtoharden.com/guides/claude-code/ v1.1.1, 2026-10-04, MIT, author Justin Pagano, marked ai-drafted. The only benchmark-shaped document for Claude Code: controls 1.1 to 5.3 in three tiers (L1 Crawl, L2 Walk, L3 Run), each mapped to NIST 800-53, SOC 2 and ISO 27001. Confidence: **control numbers, levels and NIST mappings from the guide**. Items that live outside the machine (external sandbox tooling, CI/CD, the analytics API, incident response, Cowork governance) are manual controls.

### Trail of Bits claude-code-config (`trailofbits_config`)

URL: https://github.com/trailofbits/claude-code-config (settings.json). An opinionated baseline: Read deny rules for SSH, cloud, kube, gh, npm, keychain and wallet paths, Edit denies for shell startup files, two PreToolUse hooks, project MCP auto-approval off, telemetry opt-outs. They run bypass mode plus the sandbox, a useful counter-opinion to How to Harden. Confidence: **exact rules from the file**.

### OWASP Top 10 for Agentic Applications 2026 (`owasp_agentic`)

URL: https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ (published 2025-12-09). ASI01 Agent Goal Hijack, ASI02 Tool Misuse and Exploitation, ASI03 Identity and Privilege Abuse, ASI04 Agentic Supply Chain Vulnerabilities, ASI05 Unexpected Code Execution, ASI06 Memory and Context Poisoning, ASI07 Insecure Inter-Agent Communication, ASI08 Cascading Failures, ASI09 Human-Agent Trust Exploitation, ASI10 Rogue Agents. Confidence: **titles from secondary sources** (Giskard, Cycode, Teleport agree); the official PDF is an image and could not be text-verified.

### OWASP Agentic Skills Top 10 (`owasp_agentic_skills`)

URL: https://owasp.org/www-project-agentic-skills-top-10/ and https://github.com/OWASP/www-project-agentic-skills-top-10 (v1.0-2026, leads Ken Huang and Fabio Cerullo). AST01 Malicious Skills, AST02 Supply Chain Compromise, AST03 Over-Privileged Skills, AST04 Insecure Metadata, AST05 Untrusted External Instructions, AST06 Weak Isolation, AST07 Update Drift, AST08 Poor Scanning, AST09 No Governance, AST10 Cross-Platform Reuse. Its checklist cites Claude Code CVE-2025-59536 and `.claude/settings.json` by name. Confidence: **titles verified on the project site**.

### OWASP MCP Top 10 (`owasp_mcp_top_10`)

Version 0.1 (2025). MCP01 Token Mismanagement and Secret Exposure, MCP02 Privilege Escalation via Scope Creep, MCP03 Tool Poisoning, MCP04 Software Supply Chain Attacks, MCP05 Command Injection and Execution, MCP06 Intent Flow Subversion, MCP07 Insufficient Authentication and Authorization, MCP08 Lack of Audit and Telemetry, MCP09 Shadow MCP Servers, MCP10 Context Injection and Over Sharing. Confidence: **titles from a secondary source** (cycode.com/blog/owasp-mcp-top-10); the official project page was not located.

### OWASP Top 10 for LLM Applications 2025 (`owasp_llm_2025`)

URL: https://genai.owasp.org/llm-top-10/. Kept for the original 32 controls. Confidence: **verified titles** for LLM01, LLM02, LLM03 and LLM06.

### CSA Agentic MCP Security Best Practices (`csa_agentic_mcp`, `csa_mcp_level_1..4`)

URL: https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/ (draft, 2026-03-27). Seven control domains (3.1 authentication and authorization, 3.2 tool description integrity, 3.3 session management, 3.4 message signing, 3.5 supply chain, 3.6 sandboxing and isolation, 3.7 monitoring) and a four-level cumulative maturity model, cross-mapped by CSA to ASI, CSA AICM and ATLAS. Most of it describes server-side and organizational practice, so most items are manual. Confidence: **domains and levels from the guide**.

### MITRE ATLAS (`mitre_atlas`)

URL: https://atlas.mitre.org, dataset https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml. Agent techniques AML.T0051.001 indirect prompt injection, T0053 tool invocation, T0080 context poisoning, T0081 modify agent configuration, T0083 credentials from agent configuration, T0084 discover agent configuration, T0086 exfiltration via tool invocation, T0098 tool credential harvesting, T0101 data destruction, T0104 publish poisoned tool, T0110 tool poisoning; mitigations M0026 to M0033; case studies CS0041 rules-file backdoor, CS0045 Cursor MCP exfiltration, CS0047 Amazon Q, CS0049 ClawdBot skill, CS0053 and CS0054 poisoned MCP servers. Confidence: **ids and names verified from the dataset**.

### CIS Controls v8.1 (`cis_controls_v8`)

URL: https://www.cisecurity.org/controls/v8-1. Safeguard numbers on the original 32 controls. The "AI agents companion guide" URL that earlier versions of this page cited is dead. Confidence: **safeguard numbers**.

### AWS control framework for AI coding agents (`aws_coding_agent_framework`)

AWS Security Blog post with author-time and build-time pillars and risks R001 to R007. Kept for the original 32 controls. Confidence: **risk ids from the post**.

### Anthropic CISO guide to agentic AI (`anthropic_ciso_guide`)

URL: https://claude.com/blog/ciso-guide-to-agentic-ai (2026-07-17, Jason Clinton, Deputy CISO). Four assessment questions (untrusted content, actions and identity, blast radius, observability) and seven control requirements (identity through the IdP, connector allowlists, per-tool approval, sandboxed execution without production credentials, egress allowlisting through a proxy, telemetry to the SIEM, an org-wide off switch). Confidence: **questions and controls from the post**; names no Claude Code settings, so the mapping is by meaning.

### CrowdStrike secure agent harness (`crowdstrike_harness`)

URL: https://www.crowdstrike.com/en-us/blog/secure-agent-harness-execution-preventing-escape/ (2026-08-04). Seven layers: network isolation, VM isolation, OS containment, process capability confinement, tool-call mediation, command-line action control, resource and economic containment. Written for hosted harnesses, so layers 2, 3 and 7 are largely manual. Confidence: **layer names from the post**.

### Pillar SAIL 2.0 (`pillar_sail`)

URL: https://www.pillar.security/sail (page updated 2026-08-07). Seven lifecycle phases, 91 entries; this mod maps the nine posture entries that name coding agents, MCP servers, sandboxes or configuration drift. The page states no licence, so only entry numbers and titles are reproduced. Confidence: **entry numbers and titles from the page**.

## Research that shaped the controls, not benchmarks

- arXiv 2608.23550, Ting Yan, "When Do Not Is Not Deny": of 481 public CLAUDE.md files, only 4 to 16 percent of security rules had an enforceable built-in equivalent. This is why every reason in this mod names a setting, never a sentence to put in CLAUDE.md.
- arXiv 2608.05223, Yang et al.: 2,826 synthesized malicious skill files exploited Gemini CLI in about 96 percent of runs. This is why skills are a first-class inventory (SC-09 to SC-13).
- arXiv 2608.02670, Davidovich et al., Boundary-Bench: hardening (scoped credentials, restricted egress, read-only filesystems, non-root) costs up to 18 points of task success. This is why `var.deployment` exists instead of one strict profile for everyone.
- Pillar Security's four-layer model (usage discovery, agent inventory, configuration posture, pre-action control): this mod is layer 3 only, by design.
