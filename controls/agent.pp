benchmark "agent_configuration" {
  title       = "2. Agent configuration"
  description = "Machine-wide settings that decide how much the other controls can protect: whether the sandbox is on, which permission mode sessions start in, whether an administrator pins policy, and whether hooks have been switched off."
  children = [
    control.sandbox_enabled,
    control.permission_mode_allowed,
    control.managed_settings_present,
    control.hooks_not_disabled_silently,
    control.auto_updates_decision,
    control.assessment_complete,
    control.launch_flags_reviewed,
    control.sdk_launchers_not_bypassed,
  ]
  tags = merge(local.common_tags, { group = "agent_configuration" })
}

control "sandbox_enabled" {
  title       = "Shell commands run inside an enforced sandbox"
  description = "The sandbox is what makes filesystem denyRead and network allowedDomains real, but enabling it is a configuration fact, not isolation. Claude Code retries a command that fails in the sandbox outside it unless allowUnsandboxedCommands is false, runs commands unsandboxed when the OS runtime is missing unless failIfUnavailable is true, runs excludedCommands outside it, and drops file isolation when filesystem.disabled is set (docs: sandboxing). This control passes only when the sandbox is on and none of those routes is open. Fix: set sandbox.enabled and sandbox.failIfUnavailable to true and sandbox.allowUnsandboxedCommands to false, and remove excludedCommands."
  severity    = "critical"
  tags = merge(local.common_tags, {
    agentreach                       = "AG-01"
    agentreach_class                 = "mapped"
    aisvs                      = "v1.01-C9.3.1"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI02 Tool Misuse"
    cis_controls_v8            = "4.1"
    aws_coding_agent_framework = "R005"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "2"
  })

  param "require_sandbox" {
    description = "Whether an enforced sandbox is required. When false an open sandbox reports info instead of alarm."
    default     = var.require_sandbox
  }

  sql = <<-EOQ
    select
      a.agent as resource,
      case
        when ${local.not_assessed_config_sql} then 'skip'
        when a.sandbox_enforced then 'ok'
        when $1::bool then 'alarm'
        else 'info'
      end as status,
      case
        when ${local.not_assessed_config_sql} then ${local.not_assessed_reason_sql}
        when a.sandbox_enforced
          then 'The sandbox is on with no way around it: no unsandboxed retry, no excludedCommands, file isolation on, and '
            || case when a.sandbox_fail_if_unavailable then 'failIfUnavailable stops Claude Code from starting without the runtime.' else 'the OS sandbox runtime is present.' end
        when not a.sandbox_enabled
          then 'sandbox.enabled is not true in managed or user settings, so shell commands run with your full file and network access. Set sandbox.enabled and sandbox.failIfUnavailable to true and sandbox.allowUnsandboxedCommands to false.'
        else 'sandbox.enabled is true, but shell commands can still run outside it: '
          || concat_ws('; ',
               case when a.sandbox_bypasses like '%unsandboxed_retry%' then 'a command that fails in the sandbox can be retried outside it (set sandbox.allowUnsandboxedCommands to false)' end,
               case when a.sandbox_bypasses like '%excluded_commands%' then a.sandbox_excluded_commands || ' excludedCommands entr' || case when a.sandbox_excluded_commands = 1 then 'y runs' else 'ies run' end || ' outside it (remove them)' end,
               case when a.sandbox_bypasses like '%runtime_missing%' then 'the OS sandbox runtime is missing, so commands run unsandboxed (install it, or set sandbox.failIfUnavailable to true)' end,
               case when a.sandbox_bypasses like '%filesystem_disabled%' then 'sandbox.filesystem.disabled turns off file isolation (remove it)' end
             ) || '.'
      end as reason,
      a.host,
      a.agent
    from agentreach_agent a
    where a.agent = 'claude_code'
    order by a.host;
  EOQ
}

control "permission_mode_allowed" {
  title       = "Default permission mode keeps a human in the loop"
  description = "dontAsk and bypassPermissions remove the approval prompt that stands between an injected instruction and its effect. auto mode replaces the human with a classifier that approves routine tool calls, a weaker check that reports as info when allowed. With no defaultMode in managed or user settings the built-in default applies, which is auto from Claude Code v2.1.283 and default before it (docs: permission-modes); when the version is unknown the mode is unknown and the control reports not assessed. Fix: set permissions.defaultMode to default, plan or acceptEdits for work on real credentials, and reserve bypassPermissions for disposable containers."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "AG-02"
    agentreach_class                 = "mapped"
    aisvs                      = "v1.01-C9.2.1"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI09 Human-Agent Trust Exploitation"
    cis_controls_v8            = "5.4"
    aws_coding_agent_framework = "R003"
    owasp_agent_cheatsheet     = "4"
    knostic_threat_model       = "2"
  })

  param "allowed_permission_modes" {
    description = "Permission modes a session may start in."
    default     = var.allowed_permission_modes
  }

  sql = <<-EOQ
    select
      a.agent as resource,
      case
        when ${local.not_assessed_config_sql} then 'skip'
        when a.effective_permission_mode = 'unknown' then 'skip'
        when a.effective_permission_mode not in (select jsonb_array_elements_text($1::jsonb)) then 'alarm'
        when a.effective_permission_mode = 'auto' then 'info'
        else 'ok'
      end as status,
      case
        when ${local.not_assessed_config_sql} then ${local.not_assessed_reason_sql}
        when a.effective_permission_mode = 'unknown'
          then 'Not assessed: no defaultMode is set and the Claude Code version is unknown, so the built-in default (auto from v2.1.283, default before) cannot be determined. Set permissions.defaultMode explicitly.'
        when a.effective_permission_mode not in (select jsonb_array_elements_text($1::jsonb))
          then 'Sessions start in ' || a.effective_permission_mode || ' mode (' || case a.permission_mode_source when 'built_in' then 'the built-in default for version ' || coalesce(nullif(a.version, ''), 'unknown') else 'from ' || a.permission_mode_source || ' settings' end || '), which is not on the allowed list. Set permissions.defaultMode to one of the allowed modes in ' || case when a.permission_mode_source = 'managed' then 'managed settings' else a.user_settings_path end || '.'
        when a.effective_permission_mode = 'auto'
          then 'Sessions start in auto mode' || case when a.permission_mode_source = 'built_in' then ' (the built-in default for version ' || coalesce(nullif(a.version, ''), 'unknown') || ')' else '' end || ': a classifier, not you, approves routine tool calls. Set permissions.defaultMode to default or plan when sessions can reach real credentials.'
        else 'Sessions start in ' || a.effective_permission_mode || ' mode (' || case a.permission_mode_source when 'built_in' then 'the built-in default for version ' || coalesce(nullif(a.version, ''), 'unknown') else 'from ' || a.permission_mode_source || ' settings' end || ').'
      end as reason,
      a.host,
      a.agent
    from agentreach_agent a
    where a.agent = 'claude_code'
    order by a.host;
  EOQ
}

control "assessment_complete" {
  title       = "The posture was fully assessed"
  description = "An empty findings list is only good news when agentreach could read every settings source and run its probes. A settings file that does not parse, or a connection with probe = false, leaves part of the posture unknown; the controls that depend on it report not assessed instead of passing. This control names what was missing. Fix: repair or make readable the files it lists, and set probe = true."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach       = "AG-06"
    agentreach_class = "agentreach_extension"
  })

  sql = <<-EOQ
    select
      a.agent as resource,
      case
        when coalesce(jsonb_array_length(a.collect_errors), 0) > 0 or not a.probed then 'alarm'
        else 'ok'
      end as status,
      case
        when coalesce(jsonb_array_length(a.collect_errors), 0) > 0
          then jsonb_array_length(a.collect_errors) || ' source(s) could not be read, so controls that depend on configuration report not assessed: '
            || (select string_agg(e, '; ') from jsonb_array_elements_text(a.collect_errors) e)
            || case when not a.probed then '. Probes were also off.' else '.' end
        when not a.probed
          then 'Probes were off (probe = false), so file, host and write reachability are unknown and the controls that need them report not assessed. Set probe = true in the connection config.'
        else 'Every settings source was read and the probes ran.'
      end as reason,
      a.host,
      a.agent
    from (select * from agentreach_agent where agent = 'claude_code') a
    order by a.host, a.agent;
  EOQ
}

control "managed_settings_present" {
  title       = "Managed settings pin policy for the machine"
  description = "Managed settings win over everything the user or a repository can write, so they are the only place a policy cannot be undone by a CLAUDE.md or a settings.local.json. Absent managed settings is normal on a personal machine and reports as info; on a fleet it is the gap to close. Fix: deploy a managed-settings.json via MDM with sandbox, permission and hook policy."
  severity    = "medium"
  tags = merge(local.common_tags, {
    agentreach                       = "AG-03"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI03 Identity and Privilege Abuse"
    cis_controls_v8            = "4.1"
    aws_coding_agent_framework = "R002"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    select
      agent as resource,
      case when managed_settings_present then 'ok' else 'info' end as status,
      case
        when managed_settings_present then 'Managed settings exist at ' || managed_settings_path || '.'
        else 'No managed settings at ' || managed_settings_path || '. User and project files set every policy; nothing is pinned by an administrator.'
      end as reason,
      agent
    from (select * from agentreach_agent where agent = 'claude_code') agentreach_agent;
  EOQ
}

control "hooks_not_disabled_silently" {
  title       = "Hooks are not globally disabled"
  description = "disableAllHooks switches off every PreToolUse and PostToolUse guardrail at once, including ones a project or administrator relies on, with no visible change in the session. Fix: remove disableAllHooks, or disable individual hooks you do not trust."
  severity    = "low"
  tags = merge(local.common_tags, {
    agentreach                       = "AG-04"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI02 Tool Misuse"
    cis_controls_v8            = "4.1"
    aws_coding_agent_framework = "Hooks: automated guardrails"
    owasp_agent_cheatsheet     = "6"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    select
      agent as resource,
      case when hooks_disabled then 'alarm' else 'ok' end as status,
      case
        when hooks_disabled then 'disableAllHooks is set, so no hook-based guardrail runs. Remove it from ' || user_settings_path || ' or managed settings.'
        else 'Hooks are enabled.'
      end as reason,
      agent
    from (select * from agentreach_agent where agent = 'claude_code') agentreach_agent;
  EOQ
}

control "auto_updates_decision" {
  title       = "Auto-update behaviour is a deliberate choice"
  description = "Auto-updates deliver security fixes quickly but also change the binary under you without review. Neither setting is wrong; this control records which one is in force so the choice is visible. Always info."
  severity    = "low"
  tags = merge(local.common_tags, {
    agentreach                       = "AG-05"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM03:2025 Supply Chain"
    owasp_agentic              = "ASI04 Agentic Supply Chain"
    cis_controls_v8            = "2.1"
    aws_coding_agent_framework = "R004"
    owasp_agent_cheatsheet     = "6"
    knostic_threat_model       = "5"
  })

  sql = <<-EOQ
    select
      agent as resource,
      'info' as status,
      case
        when auto_updates then agent || ' ' || coalesce(version, '?') || ' auto-updates (install method: ' || coalesce(install_method, 'unknown') || '). Fixes arrive fast; pin the version if you need change control.'
        else agent || ' ' || coalesce(version, '?') || ' does not auto-update (install method: ' || coalesce(install_method, 'unknown') || '). You own the upgrade cadence; track security releases.'
      end as reason,
      agent
    from (select * from agentreach_agent where agent = 'claude_code') agentreach_agent;
  EOQ
}

control "launch_flags_reviewed" {
  title       = "No launch flag skips permission checks"
  description = "A flag outranks every settings file: an alias such as alias claude='claude --dangerously-skip-permissions' starts every session in bypassPermissions while the settings still say default (docs: permission-modes, Which mode a session starts in). agentreach reads shell aliases and functions in startup files and, on a live scan, the command lines of running sessions (agentreach_launch_flag). This control alarms when the default claude command or a running session carries a bypass flag or --permission-mode bypassPermissions, and reports info when another alias does. permissions.disableBypassPermissionsMode set to disable stops the flags; then this control passes. Fix: remove the flag from the alias, or set disableBypassPermissionsMode in managed settings."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach          = "AG-07"
    agentreach_class    = "agentreach_extension"
    owasp_agentic = "ASI02 Tool Misuse"
  })

  sql = <<-EOQ
    with f as (
      select
        host,
        source,
        "default",
        case when source = 'running_session' then name else name || ' ' || source || ' (' || file || ':' || line || ')' end as place,
        flag || case when value <> '' then ' ' || value else '' end as what
      from
        agentreach_launch_flag
      where
        agent = 'claude_code'
        and (flag in ('--dangerously-skip-permissions', '--allow-dangerously-skip-permissions') or value = 'bypassPermissions')
    )
    select
      a.agent as resource,
      case
        when a.bypass_available_reason like '%disableBypassPermissionsMode%' then 'ok'
        when exists (select 1 from f where f.host = a.host and (f."default" or f.source = 'running_session')) then 'alarm'
        when exists (select 1 from f where f.host = a.host) then 'info'
        else 'ok'
      end as status,
      case
        when a.bypass_available_reason like '%disableBypassPermissionsMode%'
          then 'permissions.disableBypassPermissionsMode is disable, so bypass flags have no effect.'
        when exists (select 1 from f where f.host = a.host)
          then (select string_agg(f.what || ' on ' || f.place, '; ' order by f.place) from f where f.host = a.host)
            || case when exists (select 1 from f where f.host = a.host and (f."default" or f.source = 'running_session'))
                 then '. Sessions started this way skip permission prompts.'
                 else '. Only sessions started with that alias are affected.' end
        else 'No startup-file alias or function, and no running session, carries a bypass flag.'
      end as reason,
      a.host,
      a.agent
    from (select * from agentreach_agent where agent = 'claude_code') a
    order by a.host, a.agent;
  EOQ
}

control "sdk_launchers_not_bypassed" {
  title       = "Agent SDK applications do not start sessions in bypassPermissions"
  description = "An application built on the Agent SDK sets its sessions' permission mode in code, where no settings file shows it. In bypassPermissions every tool call runs without approval except the actions no mode auto-approves, and allowedTools does not narrow it (docs: Agent SDK permissions). agentreach reads the literal options in source files that import the SDK (agentreach_sdk_launcher, a heuristic); a mode set from a variable is reported as info. Fix: pass permissionMode dontAsk with the allowedTools the application needs, or default with a canUseTool callback, and pass settingSources [] so the machine's settings do not apply."
  severity    = "high"
  tags        = merge(local.common_tags, { agentreach = "AG-08", agentreach_class = "needs_validation" })

  sql = <<-EOQ
    select
      l.path as resource,
      case
        when l.permission_modes ? 'bypassPermissions' and not l.sandbox_enabled then 'alarm'
        when l.permission_modes ? 'bypassPermissions' or l.skip_permissions_allowed or l.dynamic_permission_mode then 'info'
        else 'ok'
      end as status,
      case
        when l.permission_modes ? 'bypassPermissions' and not l.sandbox_enabled
          then l.path || ' starts SDK sessions in bypassPermissions with no sandbox option, so every tool call the model makes runs without approval. Pass permissionMode dontAsk with the allowedTools it needs, or enable the sandbox option.'
        when l.permission_modes ? 'bypassPermissions'
          then l.path || ' starts SDK sessions in bypassPermissions with the sandbox option on: shell commands stay in the sandbox, but file edits, MCP tools and web fetches run without approval.'
        when l.skip_permissions_allowed
          then l.path || ' sets allowDangerouslySkipPermissions, so bypassPermissions is available to it; agentreach found no literal bypassPermissions mode.'
        when l.dynamic_permission_mode
          then l.path || ' sets its permission mode from a value agentreach cannot read; check what the application passes at run time (agentreach_launch_flag shows running sessions).'
        when jsonb_array_length(l.permission_modes) > 0
          then l.path || ' starts SDK sessions in ' || (select string_agg(m, ', ') from jsonb_array_elements_text(l.permission_modes) m) || '.'
        else l.path || ' sets no permission mode, so its sessions start in default mode, or the defaultMode its settings sources give them.'
      end as reason,
      l.project_dir,
      l.host
    from (select * from agentreach_sdk_launcher where agent = 'claude_code') l;
  EOQ
}
