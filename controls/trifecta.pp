# The spine of the benchmark. Simon Willison's "lethal trifecta": an agent that
# (1) can read private data, (2) is exposed to untrusted content, and (3) has a
# channel to send data out, can be made to exfiltrate. Every control here
# measures one leg; the last one counts the paths where all three meet.
# The legs themselves are defined once in controls/legs.pp.

benchmark "lethal_trifecta" {
  title       = "1. Lethal trifecta"
  description = "Private data the agent can read, untrusted content it obeys, and exit channels it can reach. Where all three exist, prompt injection becomes exfiltration. Cut any one leg and the attack path closes."
  children = [
    control.private_data_reachable,
    control.credential_files_not_denied,
    control.untrusted_instruction_sources,
    control.untrusted_mcp_servers,
    control.exit_channel_open,
    control.attack_path_count,
    control.integrity_paths,
  ]
  tags = merge(local.common_tags, { group = "lethal_trifecta" })
}

control "private_data_reachable" {
  title       = "Private data: sensitive files are not readable by the agent"
  description = "Any file in a sensitive category that the agent can open, through a shell command or the Read tool, is the private-data leg of the lethal trifecta. Readability is observed with a one-byte read as the current user; whether the agent's rules stop each tool path is inferred from the effective sandbox and permission settings, and confirmed when observed mode runs the read inside srt. A blocked shell path that a bypass can reopen says so and points at AG-01. Fix: enable and enforce the sandbox, list the path under sandbox.filesystem.denyRead, and add Read(//path) to permissions.deny."
  severity    = "critical"
  tags = merge(local.common_tags, {
    agentreach                       = "LT-01"
    agentreach_class                 = "mapped"
    aisvs                      = "v1.01-AC.3.2"
    owasp_llm_2025             = "LLM02:2025 Sensitive Information Disclosure"
    owasp_agentic              = "ASI03 Identity and Privilege Abuse"
    cis_controls_v8            = "3.3"
    aws_coding_agent_framework = "R002"
    owasp_agent_cheatsheet     = "8"
    knostic_threat_model       = "2"
  })

  param "sensitive_categories" {
    description = "agentreach_reach_file categories that count as private data."
    default     = var.sensitive_categories
  }

  sql = <<-EOQ
    with a as (select * from agentreach_agent where agent = 'claude_code'),
    files as (
      select f.*
      from (select * from agentreach_reach_file where agent = 'claude_code') f
      join a on ${format(local.same_snapshot_sql, "f")}
      where not ${local.not_assessed_probe_sql}
        and f.exists
        and f.category in (select jsonb_array_elements_text($1::jsonb))
    )
    select
      a.agent as resource,
      'skip' as status,
      ${local.not_assessed_reason_sql} as reason,
      null::int as tier,
      null::text as category,
      a.host,
      a.agent
    from a
    where ${local.not_assessed_probe_sql}
    union all
    select
      a.agent,
      'ok',
      'No file in the sensitive categories exists on this machine.',
      null, null, a.host, a.agent
    from a
    where not ${local.not_assessed_probe_sql}
      and not exists (select 1 from files f where ${format(local.same_snapshot_sql, "f")})
    union all
    select
      f.path as resource,
      case
        when f.model_agrees is false then 'alarm'
        when f.reach_evidence = 'unknown' then 'skip'
        when f.reachable_via_bash or f.reachable_via_read_tool then 'alarm'
        else 'ok'
      end as status,
      case
        when f.model_agrees is false
          then 'Tier ' || f.tier || ' ' || f.category || ' file ' || f.path || ': a one-byte read inside srt ' || case when f.observed_via_sandbox then 'succeeded' else 'failed' end || ', which contradicts the modelled verdict. Treat the file as reachable until the difference is explained.'
        when f.reach_evidence = 'unknown'
          then 'Not assessed: reachability of ' || f.path || ' could not be modelled.'
        when f.reachable_via_bash or f.reachable_via_read_tool
          then 'Tier ' || f.tier || ' ' || f.category || ' file ' || f.path || ' is readable by '
            || concat_ws(' and ', case when f.reachable_via_bash then 'shell commands' end, case when f.reachable_via_read_tool then 'the Read tool' end)
            || case when not a.sandbox_enabled then ', and the sandbox is off so no denyRead rule is enforced' else '' end
            || '. ' || concat_ws(' ',
                 case when f.reachable_via_bash then case when a.sandbox_enabled then 'Add it to sandbox.filesystem.denyRead.' else 'Enable the sandbox and add it to sandbox.filesystem.denyRead.' end end,
                 case when f.reachable_via_read_tool then 'Add Read(//' || ltrim(f.path, '/') || case when f.is_dir then '/**' else '' end || ') to permissions.deny.' end)
        else 'Tier ' || f.tier || ' ' || f.category || ' file ' || f.path || ' is blocked for shell commands by ' || coalesce(nullif(f.sandbox_deny_read_rule, ''), 'file permissions')
          || ' and for the Read tool by ' || coalesce(nullif(f.permission_deny_read_rule, ''), nullif(f.read_block_rule, ''), 'file permissions') || '.'
          || case when coalesce(f.bash_bypass, '') <> '' then ' A shell command could still reach it through ' || replace(f.bash_bypass, ',', ', ') || '; see AG-01.' else '' end
          || case when f.observed_via_sandbox is false then ' Confirmed inside srt.' else '' end
      end as reason,
      f.tier,
      f.category,
      f.host,
      f.agent
    from files f
    join a on ${format(local.same_snapshot_sql, "f")}
    order by host, tier nulls first, category, resource;
  EOQ
}

control "credential_files_not_denied" {
  title       = "Private data: every sensitive file has a sandbox denyRead rule"
  description = "Checks configuration rather than effect: each existing sensitive file should be covered by a managed or user sandbox.filesystem.denyRead (or credentials.files) rule. A rule that exists but is not enforced because the sandbox is disabled still alarms, because the protection is not real."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "LT-02"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM02:2025 Sensitive Information Disclosure"
    owasp_agentic              = "ASI03 Identity and Privilege Abuse"
    cis_controls_v8            = "3.3"
    aws_coding_agent_framework = "R002"
    owasp_agent_cheatsheet     = "8"
    knostic_threat_model       = "2"
  })

  param "sensitive_categories" {
    description = "agentreach_reach_file categories that count as private data."
    default     = var.sensitive_categories
  }

  sql = <<-EOQ
    select
      f.path as resource,
      case
        when coalesce(f.sandbox_deny_read_rule, '') = '' then 'alarm'
        when not a.sandbox_enabled then 'alarm'
        else 'ok'
      end as status,
      case
        when coalesce(f.sandbox_deny_read_rule, '') = ''
          then 'No sandbox denyRead rule covers tier ' || f.tier || ' file ' || f.path || ' (' || f.category || '). Add it to sandbox.filesystem.denyRead in ' || a.user_settings_path || ' or in managed settings.'
        when not a.sandbox_enabled
          then f.path || ' is covered by ' || f.sandbox_deny_read_rule || ' but sandbox.enabled is false, so the rule is not enforced. Enable the sandbox.'
        else f.path || ' is covered by ' || f.sandbox_deny_read_rule || '.'
      end as reason,
      f.tier,
      f.category,
      f.agent
    from (select * from agentreach_reach_file where agent = 'claude_code') f
    join (select * from agentreach_agent where agent = 'claude_code') a on a.agent = f.agent
    where f.exists
      and f.category in (select jsonb_array_elements_text($1::jsonb))
    order by f.tier, f.category, f.path;
  EOQ
}

control "untrusted_instruction_sources" {
  title       = "Untrusted content: every instruction file the agent loads is one you control or have reviewed"
  description = "CLAUDE.md, rules, skills, subagents and commands are instructions the agent obeys. A file counts as an untrusted source when a plugin ships it (and the plugin is not disabled), when its last commit came from someone outside the repository's own identities, when a user other than its owner can rewrite it, or when it changed after you reviewed it. A file reviewed at its current SHA-256 in the review ledger stops counting unless others can write it. Hidden Unicode, HTML comments, external URLs and includes are review signals: they report as info, because they are reasons to read the file, not proof of an attack. Fix: review plugin content and pin plugin versions, require review on instruction-file changes from others, and restrict files to owner-write."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "LT-03"
    agentreach_class                 = "mapped"
    aisvs                      = "v1.01-AC.3.3"
    owasp_llm_2025             = "LLM01:2025 Prompt Injection"
    owasp_agentic              = "ASI01 Agent Goal Hijack"
    cis_controls_v8            = "16.1"
    aws_coding_agent_framework = "R001"
    owasp_agent_cheatsheet     = "2"
    knostic_threat_model       = "6"
  })

  sql = <<-EOQ
    with a as (select * from agentreach_agent where agent = 'claude_code'),
    files as (
      select f.*
      from (select * from agentreach_instruction_file where agent = 'claude_code') f
      join a on ${format(local.same_snapshot_sql, "f")}
      where not ${local.not_assessed_config_sql}
    )
    select a.agent as resource, 'skip' as status, ${local.not_assessed_reason_sql} as reason,
      null::text as kind, null::text as scope, null::text as project_dir, a.host, a.agent
    from a
    where ${local.not_assessed_config_sql}
    union all
    select a.agent, 'ok', 'No instruction file was found for this agent.', null, null, null, a.host, a.agent
    from a
    where not ${local.not_assessed_config_sql}
      and not exists (select 1 from files f where ${format(local.same_snapshot_sql, "f")})
    union all
    select
      f.path as resource,
      case
        when f.untrusted then 'alarm'
        when f.plugin_enabled is false then 'ok'
        when coalesce(f.review_signals, '') <> '' and not f.reviewed then 'info'
        else 'ok'
      end as status,
      case
        when f.untrusted
          then f.path || ' (' || f.kind || ') is an untrusted source: ' || f.untrusted_reason || '. '
            || case
                 when f.untrusted_reason like '%writable by%' then 'Restrict the file to owner-write.'
                 when f.untrusted_reason like '%changed since review%' then 'Read the new content before the agent obeys it.'
                 when f.untrusted_reason like 'plugin %' then 'Review the plugin''s skills, commands and subagents, pin its version, or disable it in enabledPlugins.'
                 else 'Review changes from other authors before the agent obeys them.'
               end
        when f.plugin_enabled is false
          then f.path || ' ships with disabled plugin ' || f.plugin_name || ' and does not load.'
        when coalesce(f.review_signals, '') <> '' and not f.reviewed
          then f.path || ' (' || f.kind || ') is yours, and carries review signals: ' || replace(f.review_signals, ',', ', ') || '. Read it; they are reasons to look, not proof of an attack.'
        when f.reviewed
          then f.path || ' (' || f.kind || ') was reviewed at its current content.'
        else f.path || ' (' || f.kind || ') is yours: owner-writable and not from a plugin or another author.'
      end as reason,
      f.kind,
      f.scope,
      f.project_dir,
      f.host,
      f.agent
    from files f
    order by host, status, resource;
  EOQ
}

control "untrusted_mcp_servers" {
  title       = "Untrusted content: project-scoped MCP servers carry an explicit approval decision"
  description = "A .mcp.json checked into a repository declares tool servers on behalf of everyone who clones it; their tool descriptions and results reach the model as content. Claude Code asks before using a project server and records the answer (docs: mcp, project scope). A project server with no recorded decision has never been looked at. Decisions are read from enabledMcpjsonServers, disabledMcpjsonServers and enableAllProjectMcpServers in managed, user, project and local settings and from ~/.claude.json. One row per server name per machine. Fix: approve or reject each project server when prompted, or list it in enabledMcpjsonServers or disabledMcpjsonServers."
  severity    = "medium"
  tags = merge(local.common_tags, {
    agentreach                       = "LT-04"
    agentreach_class                 = "mapped"
    aisvs                      = "v1.01-C10.4.7"
    owasp_llm_2025             = "LLM03:2025 Supply Chain"
    owasp_agentic              = "ASI04 Agentic Supply Chain"
    cis_controls_v8            = "2.1"
    aws_coding_agent_framework = "R004"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "5"
  })

  sql = <<-EOQ
    with a as (select * from agentreach_agent where agent = 'claude_code'),
    servers as (
      select m.host, m.snapshot_id, m.agent, m.name,
        count(*) as declared_in,
        bool_or(m.enabled is null) as undecided,
        bool_or(m.enabled) as approved,
        min(m.source_path) as first_path
      from (select * from agentreach_mcp_server where agent = 'claude_code') m
      join a on ${format(local.same_snapshot_sql, "m")}
      where m.scope = 'project' and not ${local.not_assessed_config_sql}
      group by m.host, m.snapshot_id, m.agent, m.name
    )
    select a.agent as resource, 'skip' as status, ${local.not_assessed_reason_sql} as reason, null::bigint as declared_in, a.host, a.agent
    from a
    where ${local.not_assessed_config_sql}
    union all
    select a.agent, 'ok', 'No project .mcp.json declares a server.', null, a.host, a.agent
    from a
    where not ${local.not_assessed_config_sql}
      and not exists (select 1 from servers s where ${format(local.same_snapshot_sql, "s")})
    union all
    select
      s.name,
      case when s.undecided then 'alarm' when s.approved then 'info' else 'ok' end,
      case
        when s.undecided
          then s.name || ' is declared in ' || s.declared_in || ' .mcp.json file(s) with no approval decision recorded (first: ' || s.first_path || '). Review it, then approve or reject it so the decision is explicit.'
        when s.approved
          then s.name || ' is a project server you approved (' || s.declared_in || ' declaration(s)). Review it again when the .mcp.json changes.'
        else s.name || ' is a project server you rejected.'
      end,
      s.declared_in,
      s.host,
      s.agent
    from servers s
    order by host, resource;
  EOQ
}

control "exit_channel_open" {
  title       = "Exit channel: shell commands cannot reach an unlisted internet host without a person approving it"
  description = "If a shell command can connect to any host and nobody approves it, one injected curl is an exfiltration channel. agentreach infers this from configuration and sends no traffic. With the sandbox off, a command that is not read-only prompts in default, acceptEdits and plan mode, goes to the classifier in auto mode, is refused in dontAsk mode and runs in bypassPermissions mode, unless a saved allow rule approves it (docs: permissions, permission-modes). With the sandbox on, a connection to a host outside sandbox.network.allowedDomains is decided by the same modes, and sandbox.network.strictAllowlist or allowManagedDomainsOnly refuses it in every mode; a command that can leave the sandbox (the unsandboxed retry, excludedCommands, no runtime) falls back to the shell rules, and an allow rule also approves the retry (docs: sandboxing, Hosts outside your allowed domains, Auto-allow mode). A saved Bash allow rule for a network-capable command (curl, ssh, an interpreter, a package manager) in a project opens the exit in that project. Status: alarm when nothing gates the connection, info when a prompt or the auto-mode classifier does, ok when it is refused. A detected egress proxy or a declared egress allowlist is reported but not verified, and lowers an alarm to info. WebFetch, MCP servers and plugin hooks are other exits; LT-06 counts them."
  severity    = "critical"
  tags = merge(local.common_tags, {
    agentreach                       = "LT-05"
    agentreach_class                 = "agentreach_extension"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI02 Tool Misuse"
    cis_controls_v8            = "12.2"
    aws_coding_agent_framework = "R005"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    with base as (select * from agentreach_agent where agent = 'claude_code'),
    -- A session started in a project takes that project's gate: its own
    -- defaultMode, sandbox setting and saved allow rules (agentreach_project).
    proj as (
      select r.host, r.snapshot_id, r.agent,
        count(*) as n,
        array_to_string((array_agg(r.project_dir order by r.project_dir))[1:3], ', ') as dirs,
        (array_agg(r.network_approval_reason order by r.project_dir))[1] as why
      from (select * from agentreach_project where agent = 'claude_code') r
      join base a on ${format(local.same_snapshot_sql, "r")}
      where r.network_approval = 'none' and a.network_approval is distinct from 'none'
      group by r.host, r.snapshot_id, r.agent
    ),
    env as (
      select e.host, e.snapshot_id,
        string_agg(e.name || case when e.declared then ' (declared)' else ' (detected)' end, ', ' order by e.name) as controls
      from agentreach_environment e
      where e.name in ('egress_allowlist', 'egress_proxy', 'system_proxy') and (e.declared or e.detected)
      group by e.host, e.snapshot_id
    ),
    v as (
      select a.*, env.controls, coalesce(proj.n, 0) as proj_n, proj.dirs as proj_dirs, proj.why as proj_why,
        coalesce(proj.n, 0) > 0 as proj_open
      from base a
      left join proj on ${format(local.same_snapshot_sql, "proj")}
      left join env on env.host = a.host and env.snapshot_id = a.snapshot_id
    )
    select
      a.agent || ':internet' as resource,
      case
        when ${local.not_assessed_config_sql} then 'skip'
        when coalesce(a.network_approval, 'unknown') = 'unknown' then 'skip'
        when (a.network_approval = 'none' or a.proj_open) and a.controls is null then 'alarm'
        when a.network_approval = 'none' or a.proj_open then 'info'
        when a.network_approval in ('prompt', 'classifier') then 'info'
        else 'ok'
      end as status,
      case
        when ${local.not_assessed_config_sql} then ${local.not_assessed_reason_sql}
        when coalesce(a.network_approval, 'unknown') = 'unknown'
          then 'Not assessed: the permission mode is unknown, so agentreach cannot tell what a shell connection to an unlisted host needs; see AG-02.'
        when a.network_approval = 'none'
          then 'Shell commands can reach any internet host with no approval: ' || a.network_approval_reason || '.'
            || ' Enforce the sandbox (AG-01), set sandbox.network.strictAllowlist to true in user or managed settings, and remove allow rules for network-capable commands.'
            || case when a.controls is not null then ' Outside the agent: ' || a.controls || '; agentreach cannot verify that it blocks this.' else '' end
        when a.proj_open
          then 'In ' || a.proj_n || ' project(s) (' || a.proj_dirs || case when a.proj_n > 3 then ', ...' else '' end || ') shell commands reach any host with no approval: '
            || a.proj_why || '. Elsewhere: ' || a.network_approval_reason || '.'
            || ' Remove allow rules for network-capable commands from those projects (and from user settings if a project defaultMode brings them back), or enforce the sandbox with allowUnsandboxedCommands set to false.'
            || case when a.controls is not null then ' Outside the agent: ' || a.controls || '; agentreach cannot verify that it blocks this.' else '' end
        when a.network_approval = 'prompt'
          then 'A shell command reaches a host outside the allowlist only after you approve it: ' || a.network_approval_reason || '.'
            || ' To refuse such hosts without asking, ' || case when a.sandbox_enabled then '' else 'enable the sandbox and ' end || 'set sandbox.network.strictAllowlist to true in user or managed settings.'
        when a.network_approval = 'classifier'
          then 'A shell command reaches a host outside the allowlist when auto mode''s classifier approves it, not a person: ' || a.network_approval_reason || '.'
            || ' To refuse such hosts, ' || case when a.sandbox_enabled then '' else 'enable the sandbox and ' end || 'set sandbox.network.strictAllowlist to true in user or managed settings.'
        else 'Shell commands cannot reach hosts outside the allowlist: ' || a.network_approval_reason || '.'
      end as reason,
      a.host,
      a.agent
    from v a
    order by a.host;
  EOQ
}

control "attack_path_count" {
  title       = "No candidate exfiltration path runs without a person approving a step"
  description = "Counts candidate confidentiality paths from agentreach_path: an untrusted source the agent loads, a private file it can open, and an exit, all able to load in the same session. Each leg is established separately from configuration and probes, so a path is a candidate, not a demonstrated attack, and every leg carries its own evidence. agentreach_path.approval is the strongest gate on any step, because the path runs unattended only when every step does: the source (a project MCP server with no decision waits for your approval; a fetched page is ungated unless a rule covers every domain, because preapproved documentation domains and domains with a saved allow rule fetch with no prompt, and the classifier never sees page content), the read (read-only shell commands run with no prompt in every mode, docs: permissions) and the exit. Each is none (the mode, an allow rule or the sandbox's auto-allow runs it), classifier (auto mode), prompt (a person approves it) or unknown. Status: alarm when some path needs no approval, info when every path needs a prompt or the classifier, ok when there is no candidate. A path through an exit you declared closed (egress_allowlist) is attested, not mitigated: agentreach has not verified the declaration, so the path still counts and the reason names it. Fix whichever leg is cheapest; the dashboard ranks them."
  severity    = "critical"
  tags = merge(local.common_tags, {
    agentreach                       = "LT-06"
    agentreach_class                 = "agentreach_extension"
    owasp_llm_2025             = "LLM01:2025 Prompt Injection"
    owasp_agentic              = "ASI01 Agent Goal Hijack"
    cis_controls_v8            = "3.3"
    aws_coding_agent_framework = "R001"
    owasp_agent_cheatsheet     = "2"
    knostic_threat_model       = "6"
  })

  param "sensitive_categories" {
    description = "agentreach_reach_file categories that count as private data."
    default     = var.sensitive_categories
  }

  sql = <<-EOQ
    with a as (select * from agentreach_agent where agent = 'claude_code'),
    p as (
      select p.host, p.snapshot_id, p.agent,
        count(*) filter (where p.approval = 'none') as open,
        count(*) filter (where p.approval in ('prompt', 'classifier')) as gated,
        count(*) filter (where coalesce(p.approval, 'unknown') = 'unknown') as unknown_gate,
        count(*) filter (where p.approval = 'classifier') as classifier,
        count(distinct p.source_id) filter (where p.approval = 'none') as sources,
        count(distinct p.target_path) filter (where p.approval = 'none') as targets,
        count(distinct p.exit_id) filter (where p.approval = 'none') as exits,
        count(distinct coalesce(p.project_dir, '')) filter (where p.approval = 'none') as sessions,
        string_agg(distinct p.exit_kind, ', ' order by p.exit_kind) filter (where p.approval = 'none') as open_exits,
        string_agg(distinct p.exit_kind, ', ' order by p.exit_kind) filter (where p.approval in ('prompt', 'classifier')) as gated_exits,
        min(p.target_tier) filter (where p.approval = 'none') as worst_tier,
        count(*) filter (where p.approval = 'none' and 'unknown' in (p.source_evidence, p.target_evidence, p.exit_evidence)) as unknown_legs,
        count(*) filter (where p.status = 'attested') as attested,
        count(*) filter (where p.approval in ('prompt', 'classifier') and p.after_source_approval = 'none') as source_only
      from (select * from agentreach_path where agent = 'claude_code') p
      join a on ${format(local.same_snapshot_sql, "p")}
      where p.kind = 'confidentiality' and p.status in ('candidate', 'attested')
        and p.target_category in (select jsonb_array_elements_text($1::jsonb))
      group by p.host, p.snapshot_id, p.agent
    )
    select
      a.agent as resource,
      case
        when ${local.not_assessed_probe_sql} then 'skip'
        when coalesce(p.open, 0) > 0 then 'alarm'
        when coalesce(p.unknown_gate, 0) > 0 then 'skip'
        when coalesce(p.gated, 0) > 0 then 'info'
        else 'ok'
      end as status,
      case
        when ${local.not_assessed_probe_sql} then ${local.not_assessed_reason_sql}
        when coalesce(p.open, 0) > 0
          then p.sources || ' untrusted source(s), ' || p.targets || ' private file(s) (worst tier ' || p.worst_tier || ') and ' || p.exits || ' exit(s) (' || p.open_exits || ') can meet with no approval at any step, in '
            || p.sessions || ' session scope(s) (machine-wide, or a project with its own legs or gates)'
            || '; agentreach lists ' || p.open || ' source-file-exit combinations. Each leg is established separately; this is not a demonstrated attack.'
            || case when p.unknown_legs > 0 then ' ' || p.unknown_legs || ' of them rest on a leg whose evidence is unknown.' else '' end
            || case when p.gated > 0 then ' Another ' || p.gated || ' need a prompt or the classifier at the exit.' else '' end
            || case when p.attested > 0 then ' ' || p.attested || ' path(s) go through an exit you declared closed; agentreach did not verify that, so they still count.' else '' end
            || ' Cut the cheapest leg: strictAllowlist with an enforced sandbox closes the shell exit, a WebFetch deny rule closes the web exit, denyRead closes files, and reviewing or disabling a source removes every path through it.'
        when coalesce(p.unknown_gate, 0) > 0
          then 'Not assessed: ' || p.unknown_gate || ' candidate path(s) have an exit whose approval is unknown because the permission mode is unknown; see AG-02.'
        when coalesce(p.gated, 0) > 0
          then p.gated || ' candidate path(s) exist, and each needs ' || case when p.classifier = p.gated then 'auto mode''s classifier' when p.classifier > 0 then 'a prompt or the classifier' else 'your approval' end
            || ' at some step (exits: ' || p.gated_exits || '). That approval is the only step between an injected instruction and the exit; cutting a leg removes the path.'
            || case when p.source_only > 0 then ' ' || p.source_only || ' of them wait only for their source to load (your approval of a project MCP server); once it loads, no later step asks you.' else '' end
            || case when p.attested > 0 then ' ' || p.attested || ' of them go through an exit you declared closed; agentreach did not verify that.' else '' end
        else 'No candidate path: no combination of untrusted source, private file and exit can meet in one session.'
      end as reason,
      a.host,
      a.agent
    from a
    left join p on ${format(local.same_snapshot_sql, "p")}
    order by a.host;
  EOQ
}
control "integrity_paths" {
  title       = "Untrusted content cannot change the agent's guardrails, CI or dependencies without a human approving the write"
  description = "An integrity path joins an untrusted source the agent loads with a file whose change alters what the agent obeys or what runs later: the agent's own settings and .mcp.json, instruction files, CI workflows, dependency manifests, git hooks and shell startup files. A path exists when a shell command can write the file (agentreach's model of the sandbox write rules plus an access(2) check) or the file tool can edit it. agentreach_path.approval is the weaker of the two gates: none when the sandbox's auto-allow, acceptEdits in the working directory, bypassPermissions or an allow rule lets the write through, classifier in auto mode, prompt when a person approves it (docs: permissions, permission-modes, sandboxing auto-allow mode). The source's own gate also counts: a project MCP server with no decision loads only once you approve it, and agentreach_path.after_source_approval shows what is left after it loads. The sandbox and permission system protect the agent's settings, but not CLAUDE.md, CI workflows or manifests. Status: alarm when some path needs no approval, info when every path needs a prompt or the classifier, ok when there is no candidate. Fix: set sandbox.autoAllowBashIfSandboxed to false or keep shell writes out of these files with denyWrite, keep a mode that prompts for edits, and review or disable the untrusted source."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach       = "LT-07"
    agentreach_class = "mapped"
    aisvs      = "v1.01-C9.2.5"
  })

  sql = <<-EOQ
    with a as (select * from agentreach_agent where agent = 'claude_code'),
    p as (
      select p.host, p.snapshot_id, p.agent,
        count(*) filter (where p.approval = 'none') as open,
        count(*) filter (where p.approval in ('prompt', 'classifier')) as gated,
        count(*) filter (where p.approval = 'classifier') as classifier,
        count(*) filter (where coalesce(p.approval, 'unknown') = 'unknown') as unknown_gate,
        count(distinct p.source_id) filter (where p.approval = 'none') as sources,
        count(distinct p.target_path) filter (where p.approval = 'none') as targets,
        string_agg(distinct p.target_category, ', ' order by p.target_category) filter (where p.approval = 'none') as categories,
        string_agg(distinct p.via, ', ' order by p.via) filter (where p.approval = 'none') as vias,
        count(distinct p.target_path) filter (where p.approval in ('prompt', 'classifier')) as gated_targets,
        coalesce(bool_or(p.target_category = 'guardrail') filter (where p.approval = 'none'), false) as guardrail
      from (select * from agentreach_path where agent = 'claude_code') p
      join a on ${format(local.same_snapshot_sql, "p")}
      where p.kind = 'integrity' and p.status = 'candidate'
      group by p.host, p.snapshot_id, p.agent
    )
    select
      a.agent as resource,
      case
        when ${local.not_assessed_probe_sql} then 'skip'
        when coalesce(p.open, 0) > 0 then 'alarm'
        when coalesce(p.unknown_gate, 0) > 0 then 'skip'
        when coalesce(p.gated, 0) > 0 then 'info'
        else 'ok'
      end as status,
      case
        when ${local.not_assessed_probe_sql} then ${local.not_assessed_reason_sql}
        when coalesce(p.open, 0) > 0
          then p.open || ' candidate integrity path(s) need no approval: ' || p.sources || ' untrusted source(s) can lead to writes on ' || p.targets || ' file(s) (' || p.categories || ') by ' || p.vias || '.'
            || case when p.guardrail then ' That includes the agent''s own settings, so an injected instruction could loosen the rules that bind it.' else '' end
            || case when p.vias like '%shell%' and a.sandbox_enabled and a.sandbox_auto_allow then ' Sandboxed shell writes run with no prompt because sandbox.autoAllowBashIfSandboxed is on; set it to false or add these files to sandbox.filesystem.denyWrite.' else '' end
            || case when p.vias like '%shell%' and not a.sandbox_enabled then ' Enforce the sandbox (AG-01) so shell writes stay in the working directory.' else '' end
            || case when a.effective_permission_mode in ('bypassPermissions', 'acceptEdits') then ' Sessions start in ' || a.effective_permission_mode || ' mode, which approves edits without you.' else '' end
        when coalesce(p.unknown_gate, 0) > 0
          then 'Not assessed: ' || p.unknown_gate || ' candidate integrity path(s) have a write whose approval is unknown because the permission mode is unknown; see AG-02.'
        when coalesce(p.gated, 0) > 0
          then p.gated || ' candidate integrity path(s) reach ' || p.gated_targets || ' file(s), and each write needs ' || case when p.classifier = p.gated then 'auto mode''s classifier' when p.classifier > 0 then 'a prompt or the classifier' else 'your approval' end
            || '. Review edits to settings, instruction files, CI and manifests before approving them; reviewing or disabling the source removes the paths.'
        else 'No candidate integrity path: no untrusted source can meet a guardrail, instruction, CI, manifest, hook or shell-startup file the agent can write.'
      end as reason,
      a.host,
      a.agent
    from a
    left join p on ${format(local.same_snapshot_sql, "p")}
    order by a.host;
  EOQ
}
