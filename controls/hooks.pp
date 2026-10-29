benchmark "hooks" {
  title       = "3. Hooks"
  description = "Hooks are shell commands the agent runs on lifecycle events, outside the sandbox and before workspace trust is evaluated. They are the guardrail layer and also the easiest persistence mechanism: whoever controls a hook's source file runs code on every tool call."
  children = [
    control.hook_sources_owner_writable,
    control.hook_sources_not_git_tracked,
    control.hook_timeouts_bounded,
    control.plugin_hooks_inventoried,
    control.plugin_hooks_outside_sandbox,
  ]
  tags = merge(local.common_tags, { group = "hooks" })
}

control "hook_sources_owner_writable" {
  title       = "Hook definitions are writable only by their owner"
  description = "A settings file that defines hooks and is writable by group or others lets any local process plant a command that runs with your privileges on every tool call. Fix: chmod the file to 0644 or tighter and check its directory permissions."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "HK-01"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM03:2025 Supply Chain"
    owasp_agentic              = "ASI05 Unexpected Code Execution"
    cis_controls_v8            = "3.3"
    aws_coding_agent_framework = "Hooks: automated guardrails"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "5"
  })

  sql = <<-EOQ
    select
      source_path || ' [' || event || coalesce(':' || nullif(matcher, ''), '') || ']' as resource,
      case when source_writable_by = 'owner' then 'ok' else 'alarm' end as status,
      case
        when source_writable_by = 'owner'
          then event || ' hook in ' || source_path || ' is owner-writable.'
        else event || ' hook in ' || source_path || ' is writable by ' || source_writable_by || '. Any local process can change the command that runs on every ' || event || '. Restrict the file to owner-write.'
      end as reason,
      scope,
      event
    from (select * from agentreach_hook where agent = 'claude_code') agentreach_hook;
  EOQ
}

control "hook_sources_not_git_tracked" {
  title       = "Hook definitions are not controlled by a shared repository"
  description = "A hook defined in a git-tracked file (.claude/settings.json in a repo, or a plugin's hooks.json) means anyone with push access to that repository runs a command on every developer machine that opens it, before the trust dialog and outside the sandbox. Fix: move hooks to user or managed settings, or require review for changes to the hook file and pin plugin versions."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "HK-02"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM03:2025 Supply Chain"
    owasp_agentic              = "ASI05 Unexpected Code Execution"
    cis_controls_v8            = "16.1"
    aws_coding_agent_framework = "R004"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "5"
  })

  sql = <<-EOQ
    select
      source_path || ' [' || event || coalesce(':' || nullif(matcher, ''), '') || ']' as resource,
      case when source_tracked_in_git then 'alarm' else 'ok' end as status,
      case
        when source_tracked_in_git and scope = 'plugin'
          then event || ' hook ships in plugin repository file ' || source_path || '. A plugin update is remote code execution on this machine; pin the plugin and review its hooks.json on update.'
        when source_tracked_in_git
          then event || ' hook is defined in git-tracked ' || source_path || '. Anyone with push access runs code on every machine that opens this project. Move it to user settings or require review on that file.'
        else event || ' hook in ' || source_path || ' is not under shared version control.'
      end as reason,
      scope,
      event
    from (select * from agentreach_hook where agent = 'claude_code') agentreach_hook;
  EOQ
}

control "hook_timeouts_bounded" {
  title       = "Hook timeouts stay within the allowed window"
  description = "A hook with no timeout inherits the agent default (60 seconds). A hook that declares a longer timeout can hold a tool call, and its process, open for that long. Fix: set timeout on each hook to the smallest value that works."
  severity    = "low"
  tags = merge(local.common_tags, {
    agentreach                       = "HK-03"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI02 Tool Misuse"
    cis_controls_v8            = "4.1"
    aws_coding_agent_framework = "Hooks: automated guardrails"
    owasp_agent_cheatsheet     = "6"
    knostic_threat_model       = "5"
  })

  param "max_hook_timeout_seconds" {
    description = "Longest timeout a hook may declare."
    default     = var.max_hook_timeout_seconds
  }

  sql = <<-EOQ
    select
      source_path || ' [' || event || coalesce(':' || nullif(matcher, ''), '') || ']' as resource,
      case
        when timeout is null then 'ok'
        when timeout > $1::int then 'alarm'
        else 'ok'
      end as status,
      case
        when timeout is null then event || ' hook uses the default timeout.'
        when timeout > $1::int then event || ' hook in ' || source_path || ' declares a ' || timeout || 's timeout, above the ' || $1::text || 's limit. Lower it or move the work out of the hook.'
        else event || ' hook declares a ' || timeout || 's timeout.'
      end as reason,
      scope,
      event
    from (select * from agentreach_hook where agent = 'claude_code') agentreach_hook
    where hook_type = 'command';
  EOQ
}

control "plugin_hooks_inventoried" {
  title       = "Plugin hooks are inventoried"
  description = "Every installed plugin that ships hooks gets a row listing how many hooks it installs, on which events, and whether the plugin is enabled. Plugins are third-party code that runs on your lifecycle events; this is the list to review when you add or update one. Always info."
  severity    = "low"
  tags = merge(local.common_tags, {
    agentreach                       = "HK-04"
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
      plugin_name as resource,
      'info' as status,
      plugin_name || case when plugin_enabled is distinct from false then ' (enabled)' else ' (disabled, does not load)' end
        || ' installs ' || count(*) || ' hook(s) on ' || string_agg(distinct event, ', ' order by event) || ' from ' || min(source_path) || '.' as reason,
      scope,
      plugin_enabled
    from (select * from agentreach_hook where agent = 'claude_code') agentreach_hook
    where scope = 'plugin'
    group by plugin_name, scope, plugin_enabled
    order by plugin_name;
  EOQ
}

control "plugin_hooks_outside_sandbox" {
  title       = "Plugin hooks that run outside the sandbox are known and reviewed"
  description = "Hooks run as your user, outside the sandbox, so a hook from an enabled plugin can read any file you can and connect anywhere whatever the sandbox state. Only hooks that actually run count: disableAllHooks, allowManagedHooksOnly and a disabled plugin each stop them (docs: hooks, settings). With the sandbox off a plugin hook is one of several open exits and alarms; with it on it may be the only exit left and reports info so it stays visible. Fix: disable plugins whose hooks you have not read, pin the ones you keep, and prefer hooks defined in your own user settings."
  severity    = "medium"
  tags = merge(local.common_tags, {
    agentreach                       = "HK-05"
    agentreach_class                 = "mapped"
    aisvs                      = "v1.01-C9.3.1"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI05 Unexpected Code Execution"
    cis_controls_v8            = "12.2"
    aws_coding_agent_framework = "R005"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "5"
  })

  sql = <<-EOQ
    with a as (select * from agentreach_agent where agent = 'claude_code'),
    h as (
      select h.host, h.snapshot_id, h.agent, h.plugin_name,
        count(*) as hooks,
        string_agg(distinct h.event, ', ' order by h.event) as events
      from (select * from agentreach_hook where agent = 'claude_code') h
      join a on ${format(local.same_snapshot_sql, "h")}
      where h.scope = 'plugin' and h.runs and not ${local.not_assessed_config_sql}
      group by h.host, h.snapshot_id, h.agent, h.plugin_name
    )
    select a.agent as resource, 'skip' as status, ${local.not_assessed_reason_sql} as reason, a.host, a.agent
    from a
    where ${local.not_assessed_config_sql}
    union all
    select a.agent, 'ok', 'No plugin hook runs.', a.host, a.agent
    from a
    where not ${local.not_assessed_config_sql}
      and not exists (select 1 from h where ${format(local.same_snapshot_sql, "h")})
    union all
    select
      h.plugin_name,
      case when a.sandbox_enabled then 'info' else 'alarm' end,
      h.plugin_name || ' runs ' || h.hooks || ' hook(s) on ' || h.events || ' outside the sandbox'
        || case when a.sandbox_enabled
             then '. The sandbox does not cover hooks, so this is an exit even now; read the plugin''s hooks and pin its version.'
             else ', and the sandbox is off, so it is one of several open exits. Read the plugin''s hooks or disable the plugin in enabledPlugins.'
           end,
      h.host,
      h.agent
    from h
    join a on ${format(local.same_snapshot_sql, "h")}
    order by host, resource;
  EOQ
}
