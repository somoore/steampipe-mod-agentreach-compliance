# Hardening settings: one control per Claude Code setting that a published
# profile or guide asks for. These are the atoms the framework benchmarks in
# controls/frameworks/ compose. They read agentreach_setting only; the lethal
# trifecta controls measure effect, these measure configuration.
#
# Three SQL templates, chosen by how Claude Code treats the key:
#
#   managed_only_sql  the key is ignored outside managed settings
#                     (managed-settings.json, MDM, or server-managed cache)
#   scalar_sql        one value per key, combined per key as the comment on
#                     the template says (precedence, strictest or weakest)
#   list_sql          lists merge across managed and user; project and local
#                     entries protect their own project only
#
# Placeholders: __KEY__ setting key; __COND__ boolean SQL over `value`
# (jsonb); __FIX__ the sentence that names the fix; __ABSENT__ the status
# when the key is set nowhere; __ABSENT_REASON__ the sentence for that case.
# $1 is var.deployment.

locals {
  # Every template returns one row per machine (host and snapshot) so a
  # fleet connection never mixes one machine's settings into another's.
  managed_only_sql = <<-EOQ
    with seen as (
      select host, snapshot_id, scope, source_path, coalesce((__COND__), false) as ok
      from (select * from agentreach_setting where agent = 'claude_code') agentreach_setting
      where applies and key = '__KEY__'
    )
    select
      a.agent as resource,
      case
        when e.managed_n > 0 then 'ok'
        when e.lower_n > 0 then 'alarm'
        when $1 = 'local' then 'skip'
        else 'alarm'
      end as status,
      case
        when e.managed_n > 0
          then '__KEY__ is set in managed settings (' || e.managed_path || ').'
        when e.lower_n > 0
          then '__KEY__ is set in ' || e.lower_scopes || ' settings, where Claude Code ignores it. It only takes effect in managed settings: ' || a.managed_settings_path || ' or the server-managed policy. Move it there.'
        when $1 = 'local'
          then '__KEY__ is a managed-only setting and a local deployment has no administrator to set it.'
        else '__KEY__ is not set in managed settings. __FIX__'
      end as reason,
      $1 as deployment,
      a.host,
      a.agent
    from (select * from agentreach_agent where agent = 'claude_code') a
    cross join lateral (
      select
        count(*) filter (where scope = 'managed' and ok) as managed_n,
        min(source_path) filter (where scope = 'managed' and ok) as managed_path,
        count(*) filter (where scope <> 'managed' and ok) as lower_n,
        string_agg(distinct scope, ', ') filter (where scope <> 'managed' and ok) as lower_scopes
      from seen s where s.host = a.host and s.snapshot_id = a.snapshot_id
    ) e;
  EOQ

  # scalar_sql reads each key the way Claude Code combines it
  # (settings-reference, per key):
  #   precedence  managed, then user; a project or local file can override
  #               it in its own project (most keys)
  #   strictest   any file that sets the protective value wins; a project
  #               file protects only its own project (enableArtifact,
  #               syncClaudeAiSkills, syncClaudeAiPlugins, crossSessionInbound)
  #   weakest     the loosest honored value wins (skipDangerousModePermissionPrompt:
  #               true in any user, local or managed file skips the dialog)
  # Only the scopes where Claude Code reads the key count; values in other
  # scopes are named as ignored. Sandbox keys skip while the sandbox is off.
  scalar_sql = <<-EOQ
    with params as (
      select
        case '__KEY__'
          when 'enableArtifact' then 'strictest'
          when 'syncClaudeAiSkills' then 'strictest'
          when 'syncClaudeAiPlugins' then 'strictest'
          when 'crossSessionInbound' then 'strictest'
          when 'skipDangerousModePermissionPrompt' then 'weakest'
          else 'precedence'
        end as k,
        case '__KEY__'
          when 'autoMode.classifyAllShell' then array['managed', 'user']
          when 'skipDangerousModePermissionPrompt' then array['managed', 'user', 'local']
          when 'syncClaudeAiSkills' then array['managed', 'user', 'local']
          when 'syncClaudeAiPlugins' then array['managed', 'user', 'local']
          else array['managed', 'user', 'project', 'local']
        end as honored
    ),
    seen as (
      select host, snapshot_id, scope, source_path,
        case scope when 'managed' then 0 when 'user' then 1 else 2 end as prec,
        scope = any((select honored from params)::text[]) as h,
        coalesce((__COND__), false) as ok
      from (select * from agentreach_setting where agent = 'claude_code') agentreach_setting
      where applies and key = '__KEY__'
    ),
    v as (
      select a.*, (select k from params) as k, t.top_scope, t.top_path, t.satisfied, e.*
      from (select * from agentreach_agent where agent = 'claude_code') a
      left join lateral (
        select scope as top_scope, source_path as top_path, ok as satisfied
        from seen s
        where s.host = a.host and s.snapshot_id = a.snapshot_id and s.h and s.scope in ('managed', 'user')
        order by prec, source_path limit 1
      ) t on true
      cross join lateral (
        select
          count(*) filter (where h) as n_all,
          string_agg(source_path, ', ' order by source_path) filter (where h) as all_paths,
          count(*) filter (where h and scope in ('project', 'local') and not ok) as weak_n,
          string_agg(source_path, ', ' order by source_path) filter (where h and scope in ('project', 'local') and not ok) as weak_paths,
          count(*) filter (where h and scope in ('project', 'local') and ok) as strong_n,
          string_agg(source_path, ', ' order by source_path) filter (where h and scope in ('project', 'local') and ok) as strong_paths,
          count(*) filter (where h and not ok) as loose_n,
          string_agg(source_path, ', ' order by source_path) filter (where h and not ok) as loose_paths,
          count(*) filter (where h and scope in ('managed', 'user') and ok) as strict_n,
          coalesce(bool_or(scope = 'managed') filter (where h and ok), false) as strict_managed,
          string_agg(source_path, ', ' order by source_path) filter (where h and scope in ('managed', 'user') and ok) as strict_paths,
          string_agg(scope || ' ' || source_path, ', ' order by source_path) filter (where not h) as ignored_paths
        from seen s where s.host = a.host and s.snapshot_id = a.snapshot_id
      ) e
    )
    select
      e.agent as resource,
      case
        when '__KEY__' like 'sandbox.%' and not e.sandbox_enabled then 'skip'
        when e.k = 'weakest' and e.loose_n > 0 then 'alarm'
        when e.k = 'weakest' and e.n_all = 0 then __ABSENT__
        when e.k = 'weakest' then 'ok'
        when e.k = 'strictest' and e.strict_n > 0 and not e.strict_managed and $1 = 'enterprise' then 'info'
        when e.k = 'strictest' and e.strict_n > 0 then 'ok'
        when e.k = 'strictest' and e.strong_n > 0 then 'info'
        when e.k = 'strictest' and e.n_all = 0 then __ABSENT__
        when e.k = 'strictest' then 'alarm'
        when e.top_scope is null and e.weak_n > 0 then 'alarm'
        when e.top_scope is null then __ABSENT__
        when not e.satisfied then 'alarm'
        when e.top_scope <> 'managed' and e.weak_n > 0 then 'alarm'
        when e.top_scope <> 'managed' and $1 = 'enterprise' then 'info'
        else 'ok'
      end as status,
      case
        when '__KEY__' like 'sandbox.%' and not e.sandbox_enabled
          then 'Not applicable: the sandbox is off, so __KEY__ has no effect. Enable the sandbox first (AG-01).'
        when e.k = 'weakest' and e.loose_n > 0
          then '__KEY__ is set to a weaker value in ' || e.loose_paths || ', and the loosest value in any file applies. __FIX__'
        when e.k = 'weakest' and e.n_all = 0 then '__ABSENT_REASON__'
        when e.k = 'weakest' then '__KEY__ meets the requirement in every file that sets it (' || e.all_paths || ').'
        when e.k = 'strictest' and e.strict_n > 0 and not e.strict_managed and $1 = 'enterprise'
          then '__KEY__ is set in user settings (' || e.strict_paths || '), not in managed settings. Enforce it in ' || e.managed_settings_path || ' or the server-managed policy.'
        when e.k = 'strictest' and e.strict_n > 0
          then '__KEY__ is set in ' || e.strict_paths || '; the strictest value any file sets applies.'
        when e.k = 'strictest' and e.strong_n > 0
          then '__KEY__ meets the requirement only in ' || e.strong_n || ' project or local settings file(s) (' || e.strong_paths || '), so it applies in those projects only. __FIX__'
        when e.k = 'strictest' and e.n_all = 0 then '__ABSENT_REASON__'
        when e.k = 'strictest' then '__KEY__ is set, but no file sets the required value (' || e.all_paths || '). __FIX__'
        when e.top_scope is null and e.weak_n > 0
          then '__KEY__ is not set in managed or user settings, and ' || e.weak_n || ' project or local settings file(s) set a weaker value: ' || e.weak_paths || '. Remove it there. __FIX__'
        when e.top_scope is null then '__ABSENT_REASON__'
        when not e.satisfied then '__KEY__ in ' || e.top_path || ' does not meet the requirement. __FIX__'
        when e.top_scope <> 'managed' and e.weak_n > 0
          then '__KEY__ is set in ' || e.top_path || ' but ' || e.weak_n || ' project or local settings file(s) weaken it: ' || e.weak_paths || '. Remove the overrides or enforce the key in managed settings.'
        when e.top_scope <> 'managed' and $1 = 'enterprise'
          then '__KEY__ is set in user settings (' || e.top_path || '), not in managed settings, so a project file can override it. Enforce it in ' || e.managed_settings_path || ' or the server-managed policy.'
        else '__KEY__ is set in ' || e.top_scope || ' settings (' || e.top_path || ').'
      end
        || coalesce(' Ignored where Claude Code does not read it: ' || e.ignored_paths || '.', '') as reason,
      $1 as deployment,
      e.host,
      e.agent
    from v e;
  EOQ

  # Lists merge across scopes (settings, "How settings are merged"), so the
  # condition is tested on the managed and user entries together. Entries in
  # a project or local file protect that project only and are named.
  list_sql = <<-EOQ
    with rows as (
      select host, snapshot_id, scope, value, source_path from (select * from agentreach_setting where agent = 'claude_code') agentreach_setting
      where applies and key = '__KEY__' and jsonb_typeof(value) = 'array'
    ),
    v as (
      select a.*, m.*, p.*
      from (select * from agentreach_agent where agent = 'claude_code') a
      cross join lateral (
        select
          count(*) as n,
          string_agg(source_path, ', ' order by source_path) as paths,
          (select __COND__ from (select coalesce(jsonb_agg(x), '[]'::jsonb) as value
             from rows r, jsonb_array_elements(r.value) x
             where r.host = a.host and r.snapshot_id = a.snapshot_id and r.scope in ('managed', 'user')) merged) as hit,
          (select __COND__ from (select coalesce(jsonb_agg(x), '[]'::jsonb) as value
             from rows r, jsonb_array_elements(r.value) x
             where r.host = a.host and r.snapshot_id = a.snapshot_id and r.scope = 'managed') merged) as in_managed
        from rows r where r.host = a.host and r.snapshot_id = a.snapshot_id and r.scope in ('managed', 'user')
      ) m
      cross join lateral (
        select count(*) as proj_n, string_agg(source_path, ', ' order by source_path) as proj_paths
        from rows where rows.host = a.host and rows.snapshot_id = a.snapshot_id and rows.scope in ('project', 'local') and (__COND__)
      ) p
    )
    select
      e.agent as resource,
      case
        when e.hit and not e.in_managed and $1 = 'enterprise' then 'info'
        when e.hit then 'ok'
        when e.n = 0 and e.proj_n = 0 then __ABSENT__
        else 'alarm'
      end as status,
      case
        when e.hit and not e.in_managed and $1 = 'enterprise'
          then '__KEY__ contains the entry in user settings (' || e.paths || '), not in managed settings. Enforce it in ' || e.managed_settings_path || ' or the server-managed policy.'
        when e.hit then '__KEY__ contains the entry (' || e.paths || ').'
        when e.n = 0 and e.proj_n = 0 then '__ABSENT_REASON__'
        when e.proj_n > 0
          then '__KEY__ carries the entry only in ' || e.proj_n || ' project or local settings file(s) (' || e.proj_paths || '), which protect those projects only. __FIX__'
        else '__KEY__ is set but does not contain the required entry. __FIX__'
      end as reason,
      $1 as deployment,
      e.host,
      e.agent
    from v e;
  EOQ

  absent_alarm        = "'alarm'"
  absent_ok           = "'ok'"
  absent_info         = "'info'"
  absent_skip_local   = "case when $1 = 'local' then 'skip' else 'alarm' end"
  cond_true           = "value = 'true'::jsonb"
  cond_false          = "value = 'false'::jsonb"
  cond_not_true       = "value is distinct from 'true'::jsonb"
  cond_array          = "jsonb_typeof(value) = 'array'"
  cond_nonempty_array = "jsonb_typeof(value) = 'array' and jsonb_array_length(value) > 0"
  cond_empty_array    = "jsonb_typeof(value) = 'array' and jsonb_array_length(value) = 0"
  cond_set            = "value is not null and value <> 'null'::jsonb and value <> '\"\"'::jsonb"
}

benchmark "hardening" {
  title       = "7. Hardening settings"
  description = "One control per Claude Code setting that a published profile or guide requires: Anthropic's example profiles, How to Harden, Trail of Bits, and the OWASP, CSA and ATLAS lists. Each control knows whether its key is managed-only and reads var.deployment to decide what counts."
  children = [
    # managed-only keys
    control.managed_permission_rules_only,
    control.managed_hooks_only,
    control.managed_mcp_servers_only,
    control.marketplaces_allowlisted,
    control.marketplaces_blocklisted,
    control.providers_restricted,
    control.sandbox_managed_domains_only,
    control.sandbox_managed_read_paths_only,
    control.plugin_only_customization,
    control.sideload_flags_disabled,
    control.remote_settings_refresh_forced,
    control.channels_disabled,
    # permission mode
    control.bypass_permissions_disabled,
    control.auto_mode_disabled,
    control.dangerous_mode_prompt_kept,
    control.auto_mode_classifies_all_shell,
    # sandbox
    control.sandbox_fail_if_unavailable,
    control.sandbox_no_unsandboxed_fallback,
    control.sandbox_no_auto_allow_bash,
    control.sandbox_no_excluded_commands,
    control.sandbox_network_allowlist_defined,
    control.sandbox_network_strict_allowlist,
    control.sandbox_no_all_unix_sockets,
    control.sandbox_no_unix_socket_allowlist,
    control.sandbox_no_local_binding,
    control.sandbox_no_weaker_nested,
    control.sandbox_no_weaker_network,
    control.sandbox_credential_env_vars_hidden,
    control.sandbox_credential_files_hidden,
    control.sandbox_deny_write_defined,
    # permission rules
    control.web_fetch_denied,
    control.web_search_denied,
    control.bash_requires_approval,
    control.network_commands_denied,
    control.destructive_commands_denied,
    control.privilege_escalation_denied,
    control.force_push_denied,
    control.shell_config_edits_denied,
    control.credential_edits_denied,
    control.credential_reads_denied_per_file,
    control.upload_tools_denied,
    # MCP, hooks, plugins
    control.project_mcp_not_auto_enabled,
    control.mcp_server_allowlist_defined,
    control.builtin_browser_mcp_denied,
    control.http_hook_urls_restricted,
    control.config_change_hook_present,
    # identity, telemetry, surface
    control.login_method_forced,
    control.login_org_forced,
    control.remote_control_disabled,
    control.telemetry_enabled,
    control.otel_exporter_configured,
    control.error_reporting_disabled,
    control.cleanup_period_bounded,
    control.subagent_depth_pinned,
    control.artifact_publishing_disabled,
    control.claude_ai_skill_sync_disabled,
    control.claude_ai_plugin_sync_disabled,
    control.cross_session_inbound_refused,
    control.home_directory_not_a_project,
  ]
  tags = merge(local.common_tags, { group = "hardening" })
}

# ---------------------------------------------------------------- managed-only

control "managed_permission_rules_only" {
  title       = "Only managed permission rules apply"
  description = "allowManagedPermissionRulesOnly makes Claude Code ignore allow, ask and deny rules from user, project and local settings and from --allowedTools, so a cloned repository cannot widen what the agent may do. Fix: set allowManagedPermissionRulesOnly to true in managed settings after the managed rule set is complete."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-01", agentreach_class = "needs_validation", owasp_agentic = "ASI03", owasp_skills = "AST02", hth = "1.1", nist_800_53 = "CM-6", anthropic_profile = "strict,bash_sandbox,hipaa", mitre_atlas = "AML.M0028" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "allowManagedPermissionRulesOnly"), "__COND__", local.cond_true), "__FIX__", "Set allowManagedPermissionRulesOnly to true in managed settings once the managed allow, ask and deny lists are complete.")
}

control "managed_hooks_only" {
  title       = "Only managed hooks run"
  description = "allowManagedHooksOnly stops hooks defined in user, project, local and plugin settings from running, so a repository or plugin cannot plant a command that fires on every tool call. Fix: set allowManagedHooksOnly to true in managed settings and ship the hooks you want there."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-02", agentreach_class = "needs_validation", owasp_agentic = "ASI05", owasp_skills = "AST02", hth = "2.2", nist_800_53 = "CM-7", anthropic_profile = "strict,hipaa", mitre_atlas = "AML.T0081" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "allowManagedHooksOnly"), "__COND__", local.cond_true), "__FIX__", "Set allowManagedHooksOnly to true in managed settings.")
}

control "managed_mcp_servers_only" {
  title       = "Only managed MCP servers load"
  description = "allowManagedMcpServersOnly limits sessions to servers delivered through managed-mcp.json or managedMcpServers, so no user, project or plugin can add a tool server. Fix: set allowManagedMcpServersOnly to true in managed settings and deliver approved servers through managed-mcp.json."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-03", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_mcp = "MCP09", hth = "2.1", nist_800_53 = "CM-7", anthropic_profile = "hipaa", csa_mcp = "3.5", mitre_atlas = "AML.T0104" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "allowManagedMcpServersOnly"), "__COND__", local.cond_true), "__FIX__", "Set allowManagedMcpServersOnly to true in managed settings.")
}

control "marketplaces_allowlisted" {
  title       = "Plugin marketplaces are allowlisted"
  description = "strictKnownMarketplaces is the only list that decides which marketplace sources users can add and install from; an empty list blocks every marketplace. Fix: set strictKnownMarketplaces in managed settings to the reviewed sources, or to [] to block plugin installs."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-04", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST02", hth = "2.2", nist_800_53 = "SI-7", anthropic_profile = "lax,strict,hipaa", mitre_atlas = "AML.T0104" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "strictKnownMarketplaces"), "__COND__", local.cond_array), "__FIX__", "Set strictKnownMarketplaces in managed settings: the reviewed marketplaces, or [] to block all plugin sources.")
}

control "marketplaces_blocklisted" {
  title       = "Known-bad plugin marketplaces are blocked"
  description = "blockedMarketplaces names marketplace sources that may never be added, which protects against a known-bad source even where strictKnownMarketplaces is not yet complete. Fix: set blockedMarketplaces in managed settings."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-05", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST02", hth = "2.2", nist_800_53 = "SI-7" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "blockedMarketplaces"), "__COND__", local.cond_nonempty_array), "__FIX__", "Set blockedMarketplaces in managed settings to any marketplace your organization has rejected.")
}

control "providers_restricted" {
  title       = "API providers are restricted"
  description = "allowedProviders limits which API endpoints a machine may use, so session content cannot be routed to a gateway, a cloud provider or a custom base URL your organization has not approved. Fix: set allowedProviders in managed settings, for example [\"anthropic\"]."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-06", agentreach_class = "needs_validation", owasp_agentic = "ASI10", hth = "5.2", nist_800_53 = "AC-3", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "allowedProviders"), "__COND__", local.cond_nonempty_array), "__FIX__", "Set allowedProviders in managed settings to the providers your organization approved.")
}

control "sandbox_managed_domains_only" {
  title       = "Only managed settings can widen the sandbox network allowlist"
  description = "sandbox.network.allowManagedDomainsOnly stops developers and project files from adding hosts to the sandbox allowlist, so the egress boundary is the one your organization set. Fix: set sandbox.network.allowManagedDomainsOnly to true in managed settings."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-07", agentreach_class = "needs_validation", owasp_agentic = "ASI02", hth = "3.1", nist_800_53 = "SC-7", anthropic_profile = "hipaa", mitre_atlas = "AML.T0086", ciso_guide = "5" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "sandbox.network.allowManagedDomainsOnly"), "__COND__", local.cond_true), "__FIX__", "Set sandbox.network.allowManagedDomainsOnly to true in managed settings.")
}

control "sandbox_managed_read_paths_only" {
  title       = "Only managed settings can re-open blocked read paths"
  description = "sandbox.filesystem.allowManagedReadPathsOnly stops a user or project allowRead entry from re-opening a path that managed denyRead blocked. Fix: set sandbox.filesystem.allowManagedReadPathsOnly to true in managed settings."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-08", agentreach_class = "needs_validation", owasp_agentic = "ASI03", hth = "3.1", nist_800_53 = "AC-3", anthropic_profile = "hipaa", mitre_atlas = "AML.T0083" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "sandbox.filesystem.allowManagedReadPathsOnly"), "__COND__", local.cond_true), "__FIX__", "Set sandbox.filesystem.allowManagedReadPathsOnly to true in managed settings.")
}

control "plugin_only_customization" {
  title       = "Skills, agents, hooks and MCP come only from managed plugins"
  description = "strictPluginOnlyCustomization makes Claude Code load skills, agents, hooks and MCP servers only from plugins that managed settings enable, so nothing a developer or repository adds to .claude/ takes effect. Fix: set strictPluginOnlyCustomization to true in managed settings."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-09", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST09", nist_800_53 = "CM-7", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "strictPluginOnlyCustomization"), "__COND__", "value = 'true'::jsonb or jsonb_typeof(value) = 'object'"), "__FIX__", "Set strictPluginOnlyCustomization to true in managed settings.")
}

control "sideload_flags_disabled" {
  title       = "Sideload flags are disabled"
  description = "disableSideloadFlags removes the command-line flags that load plugins, skills or agents from arbitrary paths, which otherwise bypass marketplace controls. Fix: set disableSideloadFlags to true in managed settings."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-10", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST02", nist_800_53 = "CM-7", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "disableSideloadFlags"), "__COND__", local.cond_true), "__FIX__", "Set disableSideloadFlags to true in managed settings.")
}

control "remote_settings_refresh_forced" {
  title       = "Sessions refuse to start on stale server-managed settings"
  description = "forceRemoteSettingsRefresh makes Claude Code exit at startup when it cannot fetch fresh server-managed settings, instead of running on a cached or absent policy. Fix: set forceRemoteSettingsRefresh to true in managed settings."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-11", agentreach_class = "needs_validation", owasp_agentic = "ASI10", nist_800_53 = "CM-6", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(local.managed_only_sql, "__KEY__", "forceRemoteSettingsRefresh"), "__COND__", local.cond_true), "__FIX__", "Set forceRemoteSettingsRefresh to true in managed settings.")
}

control "channels_disabled" {
  title       = "External channels are blocked"
  description = "Channels let chat integrations push messages into a session, an injection path that arrives without a file or a repository. Per the channelsEnabled reference, channels are blocked by default on Team and Enterprise plans and on Console accounts with managed settings, and allowed on Pro and Max plans and on Console accounts without managed settings; channelsEnabled true in managed settings allows them, and false is the same as unset. Fix: leave channelsEnabled unset in managed settings, or set allowedChannelPlugins to [] there."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-12", agentreach_class = "needs_validation", owasp_agentic = "ASI01", hth = "5.2", nist_800_53 = "AC-3", mitre_atlas = "AML.T0051.001" })
  param "deployment" { default = var.deployment }
  sql = <<-EOQ
    with s as (
      select host, snapshot_id, scope, key, value, source_path from (select * from agentreach_setting where agent = 'claude_code') agentreach_setting
      where applies and key in ('channelsEnabled', 'allowedChannelPlugins')
    ),
    v as (
      select a.*, e.*
      from (select * from agentreach_agent where agent = 'claude_code') a
      cross join lateral (
        select
          coalesce(bool_or(scope = 'managed' and key = 'channelsEnabled' and value = 'true'::jsonb), false) as allowed,
          coalesce(bool_or(scope = 'managed' and key = 'allowedChannelPlugins' and value = '[]'::jsonb), false) as none_allowed,
          string_agg(scope || ' ' || source_path, ', ' order by source_path) filter (where scope <> 'managed' and key = 'channelsEnabled') as ignored
        from s where s.host = a.host and s.snapshot_id = a.snapshot_id
      ) e
    )
    select
      e.agent as resource,
      case
        when e.allowed and e.none_allowed then 'ok'
        when e.allowed then 'alarm'
        when $1 in ('teams', 'enterprise') or coalesce(e.managed_source, '') <> '' then 'ok'
        else 'info'
      end as status,
      case
        when e.allowed and e.none_allowed
          then 'channelsEnabled is true in managed settings, but allowedChannelPlugins is [] there, which blocks every channel plugin.'
        when e.allowed
          then 'channelsEnabled is true in managed settings, so channel plugins on the allowlist can push messages into sessions. Remove it, or set allowedChannelPlugins in managed settings to only the channels you need.'
        when $1 in ('teams', 'enterprise') or coalesce(e.managed_source, '') <> ''
          then 'Channels are blocked: channelsEnabled is not true in managed settings, which blocks them on Team and Enterprise plans and on accounts with managed settings.'
        else 'On Pro and Max plans and Console accounts without managed settings, channels are allowed by default, and agentreach cannot see the plan; channelsEnabled false would not change that. Install no channel plugin you have not reviewed.'
      end
        || coalesce(' channelsEnabled is ignored where it is set (' || e.ignored || '): it is read from managed settings only.', '') as reason,
      $1 as deployment,
      e.host,
      e.agent
    from v e;
  EOQ
}

# ---------------------------------------------------------------- permission mode

control "bypass_permissions_disabled" {
  title       = "Bypass-permissions mode cannot be entered"
  description = "permissions.disableBypassPermissionsMode set to \"disable\" blocks --dangerously-skip-permissions and defaultMode bypassPermissions, the two ways to remove every approval prompt. Fix: set permissions.disableBypassPermissionsMode to \"disable\"; in managed settings it cannot be undone by a project file."
  severity    = "critical"
  tags = merge(local.common_tags, { agentreach = "HD-13", agentreach_class = "needs_validation", owasp_agentic = "ASI09", hth = "1.1", nist_800_53 = "AC-3", anthropic_profile = "lax,strict,hipaa", mitre_atlas = "AML.M0029", ciso_guide = "3" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "permissions.disableBypassPermissionsMode"), "__COND__", "value = '\"disable\"'::jsonb"), "__FIX__", "Set permissions.disableBypassPermissionsMode to \"disable\"."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.disableBypassPermissionsMode is not set, so any session can start with --dangerously-skip-permissions. Set it to \"disable\".")
}

control "auto_mode_disabled" {
  title       = "Auto mode is removed from the permission cycle"
  description = "disableAutoMode removes the classifier-approved auto mode, so a human sees every non-read-only action. This is the strictest posture; teams that accept auto mode should narrow its scope instead. Fix: set disableAutoMode to \"disable\"."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-14", agentreach_class = "needs_validation", owasp_agentic = "ASI09", hth = "5.2", nist_800_53 = "AC-3", mitre_atlas = "AML.M0029" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "disableAutoMode"), "__COND__", "value = '\"disable\"'::jsonb"), "__FIX__", "Set disableAutoMode to \"disable\"."), "__ABSENT__", local.absent_info), "__ABSENT_REASON__", "disableAutoMode is not set: sessions may use auto mode, where a classifier approves routine actions. Set it to \"disable\" if every action must be seen by a person.")
}

control "dangerous_mode_prompt_kept" {
  title       = "The bypass-permissions confirmation dialog is kept"
  description = "skipDangerousModePermissionPrompt true removes the dialog that confirms entering bypass-permissions mode, making an unattended full-trust session one flag away. Fix: remove skipDangerousModePermissionPrompt or set it to false."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-15", agentreach_class = "needs_validation", owasp_agentic = "ASI09", nist_800_53 = "AC-3", mitre_atlas = "AML.M0029" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "skipDangerousModePermissionPrompt"), "__COND__", local.cond_not_true), "__FIX__", "Remove skipDangerousModePermissionPrompt or set it to false."), "__ABSENT__", local.absent_ok), "__ABSENT_REASON__", "skipDangerousModePermissionPrompt is not set; the confirmation dialog stays.")
}

control "auto_mode_classifies_all_shell" {
  title       = "Auto mode sends every shell command to the classifier"
  description = "autoMode.classifyAllShell true stops auto mode from approving shell commands outright that it would otherwise treat as routine. Fix: set autoMode.classifyAllShell to true in user or managed settings."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-16", agentreach_class = "needs_validation", owasp_agentic = "ASI09", anthropic_profile = "hipaa", mitre_atlas = "AML.M0029" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "autoMode.classifyAllShell"), "__COND__", local.cond_true), "__FIX__", "Set autoMode.classifyAllShell to true."), "__ABSENT__", local.absent_info), "__ABSENT_REASON__", "autoMode.classifyAllShell is not set; auto mode approves some shell commands without the classifier. Set it to true if sessions run in auto mode.")
}

# ---------------------------------------------------------------- sandbox

control "sandbox_fail_if_unavailable" {
  title       = "Claude Code refuses to start without the sandbox"
  description = "sandbox.failIfUnavailable true makes a missing or broken sandbox a startup error instead of a silent fallback to unsandboxed commands. Fix: set sandbox.failIfUnavailable to true."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-17", agentreach_class = "needs_validation", owasp_agentic = "ASI05", owasp_skills = "AST06", hth = "3.1", nist_800_53 = "SC-39", anthropic_profile = "hipaa", mitre_atlas = "AML.M0032" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.failIfUnavailable"), "__COND__", local.cond_true), "__FIX__", "Set sandbox.failIfUnavailable to true."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "sandbox.failIfUnavailable is not set, so when the sandbox cannot start commands run unsandboxed. Set it to true.")
}

control "sandbox_no_unsandboxed_fallback" {
  title       = "Blocked commands cannot be retried outside the sandbox"
  description = "sandbox.allowUnsandboxedCommands false removes the retry-outside-the-sandbox path that otherwise turns every sandbox denial into a permission prompt. Fix: set sandbox.allowUnsandboxedCommands to false."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-18", agentreach_class = "needs_validation", owasp_agentic = "ASI05", owasp_skills = "AST06", hth = "3.1", nist_800_53 = "SC-39", anthropic_profile = "bash_sandbox,hipaa", mitre_atlas = "AML.M0032" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.allowUnsandboxedCommands"), "__COND__", local.cond_false), "__FIX__", "Set sandbox.allowUnsandboxedCommands to false."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "sandbox.allowUnsandboxedCommands is not set, so a denied command can be retried outside the sandbox after a prompt. Set it to false.")
}

control "sandbox_no_auto_allow_bash" {
  title       = "Sandboxed commands still go through permissions"
  description = "sandbox.autoAllowBashIfSandboxed false keeps the permission system in front of sandboxed commands instead of auto-approving them because the sandbox is on. Fix: set sandbox.autoAllowBashIfSandboxed to false."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-19", agentreach_class = "needs_validation", owasp_agentic = "ASI09", hth = "3.1", nist_800_53 = "AC-3", anthropic_profile = "strict,bash_sandbox", mitre_atlas = "AML.M0029" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.autoAllowBashIfSandboxed"), "__COND__", local.cond_false), "__FIX__", "Set sandbox.autoAllowBashIfSandboxed to false."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "sandbox.autoAllowBashIfSandboxed is not set, so sandboxed commands are auto-approved by default. Set it to false to keep prompts.")
}

control "sandbox_no_excluded_commands" {
  title       = "No commands are excluded from the sandbox"
  description = "sandbox.excludedCommands lists commands that always run outside the sandbox; every entry is a hole in the filesystem and network boundary. Fix: empty sandbox.excludedCommands."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-20", agentreach_class = "needs_validation", owasp_agentic = "ASI05", hth = "3.1", nist_800_53 = "SC-39", anthropic_profile = "strict,bash_sandbox" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.excludedCommands"), "__COND__", local.cond_empty_array), "__FIX__", "Empty sandbox.excludedCommands."), "__ABSENT__", local.absent_ok), "__ABSENT_REASON__", "sandbox.excludedCommands is not set; no command bypasses the sandbox.")
}

control "sandbox_network_allowlist_defined" {
  title       = "The sandbox network allowlist is defined"
  description = "sandbox.network.allowedDomains is the list of hosts sandboxed commands may reach; without it every host is open. An empty list is the tightest setting. Fix: set sandbox.network.allowedDomains to your Git host and package registry, or to []."
  severity    = "critical"
  tags = merge(local.common_tags, { agentreach = "HD-21", agentreach_class = "needs_validation", owasp_agentic = "ASI02", hth = "3.1", nist_800_53 = "SC-7", anthropic_profile = "strict,bash_sandbox,hipaa", mitre_atlas = "AML.T0086", ciso_guide = "5" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.network.allowedDomains"), "__COND__", local.cond_array), "__FIX__", "Set sandbox.network.allowedDomains to an explicit list."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "sandbox.network.allowedDomains is not set, so sandboxed commands can reach any host. Set it to the hosts the work needs, or to [].")
}

control "sandbox_network_strict_allowlist" {
  title       = "Hosts outside the allowlist are denied, not prompted"
  description = "sandbox.network.strictAllowlist true turns an unknown host into a denial instead of a prompt the agent can argue for. Fix: set sandbox.network.strictAllowlist to true in user or managed settings."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-22", agentreach_class = "needs_validation", owasp_agentic = "ASI02", hth = "3.1", nist_800_53 = "SC-7", mitre_atlas = "AML.T0086", ciso_guide = "5" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.network.strictAllowlist"), "__COND__", local.cond_true), "__FIX__", "Set sandbox.network.strictAllowlist to true."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "sandbox.network.strictAllowlist is not set, so a host outside the allowlist prompts instead of failing. Set it to true.")
}

control "sandbox_no_all_unix_sockets" {
  title       = "Sandboxed commands cannot reach every Unix socket"
  description = "sandbox.network.allowAllUnixSockets true exposes every local socket, including the Docker daemon and agent sockets, to sandboxed commands. Fix: remove it or set it to false."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-23", agentreach_class = "needs_validation", owasp_agentic = "ASI02", nist_800_53 = "SC-7", anthropic_profile = "strict,bash_sandbox,hipaa", mitre_atlas = "AML.T0086" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.network.allowAllUnixSockets"), "__COND__", local.cond_not_true), "__FIX__", "Set sandbox.network.allowAllUnixSockets to false."), "__ABSENT__", local.absent_ok), "__ABSENT_REASON__", "sandbox.network.allowAllUnixSockets is not set; Unix sockets stay closed to sandboxed commands.")
}

control "sandbox_no_unix_socket_allowlist" {
  title       = "No Unix sockets are allowlisted for sandboxed commands"
  description = "Every path in sandbox.network.allowUnixSockets is a local service a sandboxed command can talk to. Fix: empty sandbox.network.allowUnixSockets unless a specific socket is required."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-24", agentreach_class = "needs_validation", owasp_agentic = "ASI02", nist_800_53 = "SC-7", anthropic_profile = "strict,bash_sandbox" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.network.allowUnixSockets"), "__COND__", local.cond_empty_array), "__FIX__", "Empty sandbox.network.allowUnixSockets."), "__ABSENT__", local.absent_ok), "__ABSENT_REASON__", "sandbox.network.allowUnixSockets is not set; no socket is allowlisted.")
}

control "sandbox_no_local_binding" {
  title       = "Sandboxed commands cannot bind local ports"
  description = "sandbox.network.allowLocalBinding true lets a sandboxed command open a listening port, a foothold for a local relay. Fix: remove it or set it to false."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-25", agentreach_class = "needs_validation", owasp_agentic = "ASI02", nist_800_53 = "SC-7", anthropic_profile = "strict,bash_sandbox,hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.network.allowLocalBinding"), "__COND__", local.cond_not_true), "__FIX__", "Set sandbox.network.allowLocalBinding to false."), "__ABSENT__", local.absent_ok), "__ABSENT_REASON__", "sandbox.network.allowLocalBinding is not set; sandboxed commands cannot listen on ports.")
}

control "sandbox_no_weaker_nested" {
  title       = "The weaker nested sandbox is off"
  description = "sandbox.enableWeakerNestedSandbox true trades isolation for the ability to run inside a container that lacks sandbox privileges. Fix: keep it false outside such containers."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-26", agentreach_class = "needs_validation", owasp_agentic = "ASI05", hth = "3.1", nist_800_53 = "SC-39", anthropic_profile = "strict,bash_sandbox,hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.enableWeakerNestedSandbox"), "__COND__", local.cond_not_true), "__FIX__", "Set sandbox.enableWeakerNestedSandbox to false."), "__ABSENT__", local.absent_ok), "__ABSENT_REASON__", "sandbox.enableWeakerNestedSandbox is not set; the full sandbox applies.")
}

control "sandbox_no_weaker_network" {
  title       = "Weaker network isolation is off"
  description = "sandbox.enableWeakerNetworkIsolation true relaxes the network boundary of the sandbox. Fix: keep it false."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-27", agentreach_class = "needs_validation", owasp_agentic = "ASI02", nist_800_53 = "SC-7", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.enableWeakerNetworkIsolation"), "__COND__", local.cond_not_true), "__FIX__", "Set sandbox.enableWeakerNetworkIsolation to false."), "__ABSENT__", local.absent_ok), "__ABSENT_REASON__", "sandbox.enableWeakerNetworkIsolation is not set; full network isolation applies.")
}

control "sandbox_credential_env_vars_hidden" {
  title       = "Credential environment variables are hidden from sandboxed commands"
  description = "sandbox.credentials.envVars names variables such as AWS_SECRET_ACCESS_KEY and GITHUB_TOKEN that sandboxed commands never see, so a hijacked command cannot read them from its own environment. Fix: list every credential variable in sandbox.credentials.envVars with mode deny."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-28", agentreach_class = "needs_validation", owasp_agentic = "ASI03", owasp_mcp = "MCP01", hth = "3.1", nist_800_53 = "SC-28", anthropic_profile = "hipaa", mitre_atlas = "AML.T0098" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.credentials.envVars"), "__COND__", local.cond_nonempty_array), "__FIX__", "List credential variables in sandbox.credentials.envVars."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "sandbox.credentials.envVars is not set, so every exported token is visible to sandboxed commands. List AWS, GitHub, npm and Anthropic variables there with mode deny.")
}

control "sandbox_credential_files_hidden" {
  title       = "Credential files are hidden from sandboxed commands"
  description = "sandbox.credentials.files hides credential files such as ~/.aws/credentials and ~/.ssh from sandboxed commands, including every subprocess they start. Fix: list credential paths in sandbox.credentials.files with mode deny."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-29", agentreach_class = "needs_validation", owasp_agentic = "ASI03", hth = "3.1", nist_800_53 = "AC-3", anthropic_profile = "hipaa", mitre_atlas = "AML.T0083" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.credentials.files"), "__COND__", local.cond_nonempty_array), "__FIX__", "List credential paths in sandbox.credentials.files."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "sandbox.credentials.files is not set. List ~/.aws/credentials, ~/.ssh, ~/.npmrc, ~/.git-credentials, ~/.netrc and ~/.claude/.credentials.json there with mode deny.")
}

control "sandbox_deny_write_defined" {
  title       = "Sandboxed commands cannot write to credential and startup files"
  description = "sandbox.filesystem.denyWrite stops sandboxed commands from rewriting credential files and shell startup files, which is how a hijacked command persists past the session. Fix: set sandbox.filesystem.denyWrite to the credential paths plus ~/.zshrc, ~/.bashrc and ~/.gitconfig."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-30", agentreach_class = "needs_validation", owasp_agentic = "ASI05", hth = "3.1", nist_800_53 = "AC-3", anthropic_profile = "hipaa", mitre_atlas = "AML.T0081" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "sandbox.filesystem.denyWrite"), "__COND__", local.cond_nonempty_array), "__FIX__", "Set sandbox.filesystem.denyWrite."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "sandbox.filesystem.denyWrite is not set, so sandboxed commands can rewrite ~/.zshrc, ~/.ssh and other startup or credential files. List them there.")
}

# ---------------------------------------------------------------- permission rules

control "web_fetch_denied" {
  title       = "WebFetch is denied"
  description = "WebFetch runs outside the sandbox and can carry file contents to any URL in its request. Denying it closes the exit the sandbox cannot. Fix: add \"WebFetch\" to permissions.deny."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-31", agentreach_class = "needs_validation", owasp_agentic = "ASI02", hth = "3.1", nist_800_53 = "SC-7", anthropic_profile = "strict,hipaa", mitre_atlas = "AML.T0086", ciso_guide = "5" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.deny"), "__COND__", "value ? 'WebFetch'"), "__FIX__", "Add \"WebFetch\" to permissions.deny."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.deny does not exist, so WebFetch is available and runs outside the sandbox. Add \"WebFetch\" to permissions.deny.")
}

control "web_search_denied" {
  title       = "WebSearch is denied"
  description = "WebSearch sends the query text off the machine outside the sandbox, so an injected instruction can encode data into a search. Fix: add \"WebSearch\" to permissions.deny."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-32", agentreach_class = "needs_validation", owasp_agentic = "ASI02", hth = "3.1", nist_800_53 = "SC-7", anthropic_profile = "strict", mitre_atlas = "AML.T0086" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.deny"), "__COND__", "value ? 'WebSearch'"), "__FIX__", "Add \"WebSearch\" to permissions.deny."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.deny does not exist, so WebSearch is available. Add \"WebSearch\" to permissions.deny.")
}

control "bash_requires_approval" {
  title       = "Every shell command asks first"
  description = "\"Bash\" in permissions.ask means no shell command runs without a person, whatever allow rules say elsewhere. Fix: add \"Bash\" to permissions.ask."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-33", agentreach_class = "needs_validation", owasp_agentic = "ASI05", hth = "1.2", nist_800_53 = "AC-3", anthropic_profile = "strict", mitre_atlas = "AML.M0029" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.ask"), "__COND__", "value ? 'Bash'"), "__FIX__", "Add \"Bash\" to permissions.ask."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.ask does not exist; shell commands follow the session mode. Add \"Bash\" to permissions.ask to prompt for every command.")
}

control "network_commands_denied" {
  title       = "curl and wget are denied by rule"
  description = "Commands that fetch content from the web are the simplest exfiltration primitive; a deny rule stops them regardless of mode. Deny rules match the command as written, so the sandbox network allowlist is the real boundary. Fix: add \"Bash(curl *)\" and \"Bash(wget *)\" to permissions.deny."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-34", agentreach_class = "needs_validation", owasp_agentic = "ASI02", hth = "1.2", nist_800_53 = "SC-7", mitre_atlas = "AML.T0086" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.deny"), "__COND__", "exists (select 1 from jsonb_array_elements_text(value) e where e like 'Bash(curl%') and exists (select 1 from jsonb_array_elements_text(value) e where e like 'Bash(wget%')"), "__FIX__", "Add \"Bash(curl *)\" and \"Bash(wget *)\" to permissions.deny."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.deny does not exist; curl and wget follow the session mode. Add \"Bash(curl *)\" and \"Bash(wget *)\" to permissions.deny.")
}

control "destructive_commands_denied" {
  title       = "Recursive delete is denied by rule"
  description = "A deny rule for rm -rf stops the most common destructive command before any prompt. Fix: add \"Bash(rm -rf *)\" and \"Bash(rm -fr *)\" to permissions.deny, or a PreToolUse hook that redirects to trash."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-35", agentreach_class = "needs_validation", owasp_agentic = "ASI02", hth = "1.2", nist_800_53 = "CM-7", trailofbits = "deny", mitre_atlas = "AML.T0101" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.deny"), "__COND__", "exists (select 1 from jsonb_array_elements_text(value) e where e like 'Bash(rm -rf%' or e like 'Bash(rm -fr%' or e like 'Bash(rm %')"), "__FIX__", "Add \"Bash(rm -rf *)\" to permissions.deny."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.deny does not exist; rm -rf follows the session mode. Add \"Bash(rm -rf *)\" to permissions.deny.")
}

control "privilege_escalation_denied" {
  title       = "sudo is denied by rule"
  description = "A deny rule for sudo keeps the agent at your user's privilege even in auto or bypass mode. Fix: add \"Bash(sudo *)\" to permissions.deny."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-36", agentreach_class = "needs_validation", owasp_agentic = "ASI03", hth = "1.2", nist_800_53 = "AC-6", trailofbits = "deny", mitre_atlas = "AML.M0026" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.deny"), "__COND__", "exists (select 1 from jsonb_array_elements_text(value) e where e like 'Bash(sudo%')"), "__FIX__", "Add \"Bash(sudo *)\" to permissions.deny."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.deny does not exist; sudo follows the session mode. Add \"Bash(sudo *)\" to permissions.deny.")
}

control "force_push_denied" {
  title       = "Force push and hard reset are denied by rule"
  description = "git push --force and git reset --hard destroy history that a hijacked session could be told to erase. Fix: add \"Bash(git push --force*)\", \"Bash(git push *--force*)\" and \"Bash(git reset --hard*)\" to permissions.deny."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-37", agentreach_class = "needs_validation", owasp_agentic = "ASI02", nist_800_53 = "CM-7", trailofbits = "deny", mitre_atlas = "AML.T0101" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.deny"), "__COND__", "exists (select 1 from jsonb_array_elements_text(value) e where e like 'Bash(git push%force%') and exists (select 1 from jsonb_array_elements_text(value) e where e like 'Bash(git reset%--hard%')"), "__FIX__", "Add \"Bash(git push --force*)\", \"Bash(git push *--force*)\" and \"Bash(git reset --hard*)\" to permissions.deny."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.deny is not set in user or managed settings; force pushes and hard resets follow the session mode. Add \"Bash(git push --force*)\", \"Bash(git push *--force*)\" and \"Bash(git reset --hard*)\" to permissions.deny.")
}

control "shell_config_edits_denied" {
  title       = "Shell startup files cannot be edited by the agent"
  description = "An Edit deny rule for ~/.zshrc and ~/.bashrc stops the file tools from planting a command that runs in every future shell, outside any sandbox. Fix: add \"Edit(~/.zshrc)\" and \"Edit(~/.bashrc)\" to permissions.deny."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-38", agentreach_class = "needs_validation", owasp_agentic = "ASI05", nist_800_53 = "CM-7", trailofbits = "deny", mitre_atlas = "AML.T0081" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.deny"), "__COND__", "exists (select 1 from jsonb_array_elements_text(value) e where e like 'Edit(~/.zshrc%' or e like 'Edit(~/.bashrc%' or e like 'Edit(~/.profile%' or e like 'Edit(~/.bash_profile%')"), "__FIX__", "Add Edit deny rules for shell startup files to permissions.deny."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.deny does not exist; the agent can edit ~/.zshrc. Add \"Edit(~/.zshrc)\" and \"Edit(~/.bashrc)\" to permissions.deny.")
}

control "credential_edits_denied" {
  title       = "Credential files cannot be edited by the agent"
  description = "Edit deny rules for ~/.ssh, ~/.aws and ~/.config/gh stop the file tools from rewriting keys and tokens; sandbox denyWrite binds commands, not Claude's own edits. Fix: add \"Edit(~/.ssh/**)\" and \"Edit(~/.aws/**)\" to permissions.deny."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-39", agentreach_class = "needs_validation", owasp_agentic = "ASI03", nist_800_53 = "AC-3", anthropic_profile = "hipaa", trailofbits = "deny", mitre_atlas = "AML.T0081" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.deny"), "__COND__", "exists (select 1 from jsonb_array_elements_text(value) e where e like 'Edit(~/.ssh%') and exists (select 1 from jsonb_array_elements_text(value) e where e like 'Edit(~/.aws%')"), "__FIX__", "Add Edit deny rules for credential paths to permissions.deny."), "__ABSENT__", local.absent_alarm), "__ABSENT_REASON__", "permissions.deny does not exist; the agent can edit ~/.ssh and ~/.aws. Add \"Edit(~/.ssh/**)\" and \"Edit(~/.aws/**)\" to permissions.deny.")
}

control "credential_reads_denied_per_file" {
  title       = "Every tier-1 and tier-2 sensitive file has a Read deny rule"
  description = "The permissions.deny Read rule is the control that binds Claude's own file tools; the sandbox binds only commands. Each existing credential file should be covered by one. Fix: add Read(path) rules to permissions.deny for every uncovered file."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-40", agentreach_class = "needs_validation", owasp_agentic = "ASI03", hth = "1.2", nist_800_53 = "AC-3", anthropic_profile = "hipaa", trailofbits = "deny", mitre_atlas = "AML.T0083" })
  param "sensitive_categories" { default = var.sensitive_categories }
  sql = <<-EOQ
    select
      path as resource,
      case when coalesce(permission_deny_read_rule, '') <> '' then 'ok' else 'alarm' end as status,
      case
        when coalesce(permission_deny_read_rule, '') <> '' then path || ' is covered by ' || permission_deny_read_rule || '.'
        else 'No permissions.deny Read rule covers tier ' || tier || ' file ' || path || ' (' || category || '). Add Read(' || regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || case when is_dir then '/**' else '' end || ') to permissions.deny.'
      end as reason,
      tier, category, agent
    from (select * from agentreach_reach_file where agent = 'claude_code') agentreach_reach_file
    where exists and tier <= 2
      and category in (select jsonb_array_elements_text($1::jsonb))
    order by tier, category, path;
  EOQ
}

control "upload_tools_denied" {
  title       = "Tools that upload content to claude.ai are denied"
  description = "Projects, SendUserFile, ShareOnboardingGuide and Artifact send session content off the machine through channels the sandbox never sees. Fix: add them to permissions.deny where data must stay local."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-41", agentreach_class = "needs_validation", owasp_agentic = "ASI02", nist_800_53 = "SC-7", anthropic_profile = "hipaa", mitre_atlas = "AML.T0086" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "permissions.deny"), "__COND__", "value ? 'Projects' and value ? 'SendUserFile' and value ? 'Artifact'"), "__FIX__", "Add \"Projects\", \"SendUserFile\", \"ShareOnboardingGuide\" and \"Artifact\" to permissions.deny."), "__ABSENT__", local.absent_info), "__ABSENT_REASON__", "permissions.deny does not exist; upload tools are available. Add \"Projects\", \"SendUserFile\" and \"Artifact\" to permissions.deny if session content must stay on the machine.")
}

# ---------------------------------------------------------------- MCP, hooks, plugins

control "project_mcp_not_auto_enabled" {
  title       = "Project .mcp.json servers are not auto-approved"
  description = "enableAllProjectMcpServers true starts every server a cloned repository declares without the approval prompt, which is remote code execution by git clone. Fix: remove enableAllProjectMcpServers or set it to false."
  severity    = "critical"
  tags = merge(local.common_tags, { agentreach = "HD-42", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_mcp = "MCP09", hth = "2.1", nist_800_53 = "CM-7", trailofbits = "mcp", csa_mcp = "3.5", mitre_atlas = "AML.T0104" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "enableAllProjectMcpServers"), "__COND__", local.cond_not_true), "__FIX__", "Set enableAllProjectMcpServers to false."), "__ABSENT__", local.absent_ok), "__ABSENT_REASON__", "enableAllProjectMcpServers is not set; project servers prompt before they start.")
}

control "mcp_server_allowlist_defined" {
  title       = "An MCP server allowlist is defined"
  description = "allowedMcpServers limits which servers users can add by name, command or URL; without it any server can be configured. Fix: set allowedMcpServers to the reviewed servers, or to [] to block user-added servers."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-43", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_mcp = "MCP09", hth = "2.1", nist_800_53 = "CM-7", anthropic_profile = "hipaa", csa_mcp = "3.5", mitre_atlas = "AML.T0104" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "allowedMcpServers"), "__COND__", local.cond_array), "__FIX__", "Set allowedMcpServers."), "__ABSENT__", local.absent_skip_local), "__ABSENT_REASON__", "allowedMcpServers is not set, so any MCP server can be added. Set it in managed settings to the reviewed servers, or to [] to block user-added servers.")
}

control "builtin_browser_mcp_denied" {
  title       = "The built-in browser and computer-use servers are denied"
  description = "deniedMcpServers can name the built-in claude-in-chrome and computer-use servers, which the allowlist never evaluates and which can act in the user's real browser session. Fix: add {\"serverName\": \"claude-in-chrome\"} and {\"serverName\": \"computer-use\"} to deniedMcpServers."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-44", agentreach_class = "needs_validation", owasp_agentic = "ASI02", owasp_mcp = "MCP02", nist_800_53 = "CM-7", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.list_sql, "__KEY__", "deniedMcpServers"), "__COND__", "value @> '[{\"serverName\": \"claude-in-chrome\"}]'::jsonb and value @> '[{\"serverName\": \"computer-use\"}]'::jsonb"), "__FIX__", "Add claude-in-chrome and computer-use to deniedMcpServers."), "__ABSENT__", local.absent_info), "__ABSENT_REASON__", "deniedMcpServers is not set; the built-in browser and computer-use servers are available. Deny them where the agent must not act in the browser of the user.")
}

control "http_hook_urls_restricted" {
  title       = "HTTP hooks can only post to allowlisted URLs"
  description = "An HTTP hook sends every event's JSON, including tool input, to its URL. allowedHttpHookUrls limits where that can go; without it any URL in any settings file receives the stream. Fix: set allowedHttpHookUrls to the reviewed endpoints, or to [] when no HTTP hook is wanted."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "HD-45", agentreach_class = "needs_validation", owasp_agentic = "ASI07", hth = "2.2", nist_800_53 = "SC-7", anthropic_profile = "hipaa", mitre_atlas = "AML.T0086" })
  # allowedHttpHookUrls merges across every settings file (hooks, "HTTP
  # hooks"), so a repository can add its own endpoint to the allowlist.
  # allowedHttpHookUrls merges across every settings file (hooks, "HTTP
  # hooks"), so a repository can add its own endpoint to the allowlist.
  sql = <<-EOQ
    with allow as (
      select host, snapshot_id, scope, source_path, jsonb_array_length(value) as n
      from (select * from agentreach_setting where agent = 'claude_code') agentreach_setting
      where applies and key = 'allowedHttpHookUrls' and jsonb_typeof(value) = 'array'
    ),
    http as (
      select host, snapshot_id, event, coalesce(nullif(url, ''), command) as target
      from (select * from agentreach_hook where agent = 'claude_code') agentreach_hook
      where hook_type = 'http' and runs is distinct from false
    ),
    v as (
      select a.*, e.*, h.*
      from (select * from agentreach_agent where agent = 'claude_code') a
      cross join lateral (
        select
          count(*) filter (where scope in ('project', 'local') and n > 0) as proj_n,
          string_agg(source_path, ', ' order by source_path) filter (where scope in ('project', 'local') and n > 0) as proj_paths,
          count(*) filter (where scope in ('managed', 'user')) as top_n,
          string_agg(source_path, ', ' order by source_path) filter (where scope in ('managed', 'user')) as top_paths
        from allow where allow.host = a.host and allow.snapshot_id = a.snapshot_id
      ) e
      cross join lateral (
        select count(*) as http_n, string_agg(event || ' -> ' || target, '; ') as http_list
        from http where http.host = a.host and http.snapshot_id = a.snapshot_id
      ) h
    )
    select
      e.agent as resource,
      case
        when e.proj_n > 0 then 'alarm'
        when e.top_n > 0 then 'ok'
        when e.http_n > 0 then 'alarm'
        else 'info'
      end as status,
      case
        when e.proj_n > 0
          then e.proj_n || ' project or local settings file(s) add URLs to allowedHttpHookUrls (' || e.proj_paths || '). The lists merge, so a repository can allow its own endpoint. Remove the entries there and keep the allowlist in user or managed settings.'
        when e.top_n > 0
          then 'allowedHttpHookUrls is set (' || e.top_paths || ') and no project file adds to it.'
        when e.http_n > 0
          then e.http_n || ' HTTP hook(s) run and allowedHttpHookUrls is not set, so they can post event data to any URL: ' || e.http_list || '. Set allowedHttpHookUrls.'
        else 'No HTTP hooks are configured and allowedHttpHookUrls is not set. Set it to [] in user or managed settings so none can be added silently.'
      end as reason,
      e.host,
      e.agent
    from v e;
  EOQ
}

control "config_change_hook_present" {
  title       = "A ConfigChange hook audits or blocks settings changes"
  description = "The ConfigChange hook fires when settings, hooks or MCP configuration change during a session, which is how a hijacked session would widen its own permissions. Fix: add a ConfigChange hook that logs or denies the change."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-46", agentreach_class = "needs_validation", owasp_agentic = "ASI06", hth = "1.1", nist_800_53 = "AU-6", mitre_atlas = "AML.T0081" })
  # A hook counts only if it runs (disableAllHooks, allowManagedHooksOnly
  # and disabled plugins stop it) and applies to every session: managed,
  # user or plugin scope. A project hook covers that project only.
  # A hook counts only if it runs (disableAllHooks, allowManagedHooksOnly
  # and disabled plugins stop it) and applies to every session: managed,
  # user or plugin scope. A project hook covers that project only.
  sql = <<-EOQ
    with h as (
      select host, snapshot_id, scope, source_path, coalesce(runs, true) as runs, runs_reason
      from (select * from agentreach_hook where agent = 'claude_code') agentreach_hook where event = 'ConfigChange'
    ),
    v as (
      select a.*, e.*
      from (select * from agentreach_agent where agent = 'claude_code') a
      cross join lateral (
        select
          count(*) filter (where runs and scope in ('managed', 'user', 'plugin')) as global_n,
          count(*) filter (where runs) as run_n,
          string_agg(source_path, ', ' order by source_path) filter (where runs) as run_paths,
          count(*) as all_n,
          string_agg(distinct coalesce(nullif(runs_reason, ''), 'not run'), '; ') filter (where not runs) as why
        from h where h.host = a.host and h.snapshot_id = a.snapshot_id
      ) e
    )
    select
      e.agent as resource,
      case
        when e.global_n > 0 then 'ok'
        when e.run_n > 0 then 'info'
        else 'alarm'
      end as status,
      case
        when e.global_n > 0 then e.global_n || ' ConfigChange hook(s) run in every session.'
        when e.run_n > 0
          then 'ConfigChange hooks run only from ' || e.run_n || ' project or local settings file(s) (' || e.run_paths || '). Add one in user or managed settings to cover every session.'
        when e.all_n > 0
          then e.all_n || ' ConfigChange hook(s) are defined but do not run: ' || e.why || '. Add one that runs, in user or managed settings.'
        else 'No ConfigChange hook is defined, so a session can rewrite settings, hooks and MCP configuration unobserved. Add one in user or managed settings.'
      end as reason,
      e.host,
      e.agent
    from v e;
  EOQ
}

# ---------------------------------------------------------------- identity, telemetry, surface

control "login_method_forced" {
  title       = "Login is restricted to the organization's method"
  description = "forceLoginMethod stops sessions from signing in with a personal account or an API key, which would route session content outside the organization. Fix: set forceLoginMethod to claudeai or console in managed settings."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-47", agentreach_class = "needs_validation", owasp_agentic = "ASI10", hth = "5.2", nist_800_53 = "AC-3", anthropic_profile = "hipaa", ciso_guide = "1" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "forceLoginMethod"), "__COND__", local.cond_set), "__FIX__", "Set forceLoginMethod."), "__ABSENT__", local.absent_skip_local), "__ABSENT_REASON__", "forceLoginMethod is not set, so a session can sign in with a personal account. Set it in managed settings.")
}

control "login_org_forced" {
  title       = "Login is restricted to the organization"
  description = "forceLoginOrgUUID makes Claude Code exit unless the sign-in belongs to your organization, closing the personal-account bypass. Fix: set forceLoginOrgUUID to your organization ID in managed settings."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-48", agentreach_class = "needs_validation", owasp_agentic = "ASI10", hth = "5.2", nist_800_53 = "AC-3", anthropic_profile = "hipaa", ciso_guide = "1" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "forceLoginOrgUUID"), "__COND__", local.cond_set), "__FIX__", "Set forceLoginOrgUUID."), "__ABSENT__", local.absent_skip_local), "__ABSENT_REASON__", "forceLoginOrgUUID is not set, so a session can sign in to another organization. Set it in managed settings.")
}

control "remote_control_disabled" {
  title       = "Remote Control is disabled"
  description = "Remote Control lets a web client drive the local session, so a stolen short-lived credential becomes a remote shell on the developer machine. Fix: set disableRemoteControl to true where it is not needed."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-49", agentreach_class = "needs_validation", owasp_agentic = "ASI10", hth = "5.2", nist_800_53 = "AC-17", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "disableRemoteControl"), "__COND__", local.cond_true), "__FIX__", "Set disableRemoteControl to true."), "__ABSENT__", local.absent_info), "__ABSENT_REASON__", "disableRemoteControl is not set; a session can be driven from the web. Set it to true where remote control is not needed.")
}

control "telemetry_enabled" {
  title       = "OpenTelemetry is enabled"
  description = "CLAUDE_CODE_ENABLE_TELEMETRY=1 turns on the metrics and events your SIEM needs to tell agent actions from user actions. Fix: set env.CLAUDE_CODE_ENABLE_TELEMETRY to \"1\" in managed settings."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-50", agentreach_class = "needs_validation", owasp_agentic = "ASI10", owasp_mcp = "MCP08", hth = "5.1", nist_800_53 = "AU-6", anthropic_profile = "hipaa", csa_mcp = "3.7", ciso_guide = "6" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "env.CLAUDE_CODE_ENABLE_TELEMETRY"), "__COND__", "value = '\"1\"'::jsonb"), "__FIX__", "Set env.CLAUDE_CODE_ENABLE_TELEMETRY to \"1\"."), "__ABSENT__", local.absent_skip_local), "__ABSENT_REASON__", "env.CLAUDE_CODE_ENABLE_TELEMETRY is not set, so no metrics or events leave the machine for your SIEM. Set it to \"1\" with an OTEL exporter.")
}

control "otel_exporter_configured" {
  title       = "An OpenTelemetry exporter is configured"
  description = "OTEL_METRICS_EXPORTER and OTEL_LOGS_EXPORTER route telemetry to your collector; without them CLAUDE_CODE_ENABLE_TELEMETRY exports nothing. Fix: set env.OTEL_METRICS_EXPORTER and env.OTEL_LOGS_EXPORTER to otlp and point OTEL_EXPORTER_OTLP_ENDPOINT at your collector."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-51", agentreach_class = "needs_validation", owasp_agentic = "ASI10", owasp_mcp = "MCP08", hth = "5.1", nist_800_53 = "AU-6", anthropic_profile = "hipaa", csa_mcp = "3.7", ciso_guide = "6" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "env.OTEL_METRICS_EXPORTER"), "__COND__", local.cond_set), "__FIX__", "Set env.OTEL_METRICS_EXPORTER."), "__ABSENT__", local.absent_skip_local), "__ABSENT_REASON__", "env.OTEL_METRICS_EXPORTER is not set; telemetry has nowhere to go. Set it to otlp with an endpoint.")
}

control "error_reporting_disabled" {
  title       = "Error reporting to the vendor is disabled"
  description = "DISABLE_ERROR_REPORTING=1 stops crash reports, which can carry file paths and command fragments, from leaving the machine. Fix: set env.DISABLE_ERROR_REPORTING to \"1\"."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-52", agentreach_class = "needs_validation", owasp_agentic = "ASI02", nist_800_53 = "SC-7", anthropic_profile = "hipaa", trailofbits = "env" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "env.DISABLE_ERROR_REPORTING"), "__COND__", "value = '\"1\"'::jsonb"), "__FIX__", "Set env.DISABLE_ERROR_REPORTING to \"1\"."), "__ABSENT__", local.absent_info), "__ABSENT_REASON__", "env.DISABLE_ERROR_REPORTING is not set; crash reports go to the vendor. Set it to \"1\" where session content must stay local.")
}

control "cleanup_period_bounded" {
  title       = "Local transcript retention is bounded"
  description = "cleanupPeriodDays decides how long full session transcripts, which contain every file the agent read, stay on disk. Fix: set cleanupPeriodDays at or below var.max_cleanup_period_days."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-53", agentreach_class = "needs_validation", owasp_agentic = "ASI03", hth = "5.2", nist_800_53 = "SI-12", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  param "max_cleanup_period_days" { default = var.max_cleanup_period_days }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "cleanupPeriodDays"), "__COND__", "jsonb_typeof(value) = 'number' and (value::text)::numeric <= $2::numeric"), "__FIX__", "Lower cleanupPeriodDays."), "__ABSENT__", "case when 30 <= $2::numeric then 'ok' else 'alarm' end"), "__ABSENT_REASON__", "cleanupPeriodDays is not set, so transcripts are kept for the default 30 days. If that is more than var.max_cleanup_period_days, set cleanupPeriodDays to that limit or lower.")
}

control "subagent_depth_pinned" {
  title       = "Subagent spawn depth is pinned"
  description = "CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH caps how many layers of subagents can nest; the built-in default is delivered by a remote flag and can move without a release. Fix: set env.CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH explicitly, 1 to stop subagents from spawning their own."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-54", agentreach_class = "needs_validation", owasp_agentic = "ASI08", nist_800_53 = "SC-5", trailofbits = "env", mitre_atlas = "AML.T0034.002" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "env.CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH"), "__COND__", local.cond_set), "__FIX__", "Set env.CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH."), "__ABSENT__", local.absent_info), "__ABSENT_REASON__", "env.CLAUDE_CODE_MAX_SUBAGENT_SPAWN_DEPTH is not set; the nesting limit comes from a remote default. Pin it.")
}

control "artifact_publishing_disabled" {
  title       = "Artifact publishing is disabled"
  description = "The Artifact tool publishes pages to claude.ai, an exit for session content that no sandbox rule covers. Fix: set enableArtifact to false where content must stay local; a false at any scope wins."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-55", agentreach_class = "needs_validation", owasp_agentic = "ASI02", nist_800_53 = "SC-7", anthropic_profile = "hipaa", mitre_atlas = "AML.T0086" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "enableArtifact"), "__COND__", local.cond_false), "__FIX__", "Set enableArtifact to false."), "__ABSENT__", local.absent_skip_local), "__ABSENT_REASON__", "enableArtifact is not set; sessions can publish artifacts to claude.ai. Set it to false where content must stay local.")
}

control "claude_ai_skill_sync_disabled" {
  title       = "Skills do not sync from claude.ai"
  description = "syncClaudeAiSkills pulls skills from the claude.ai account into local sessions, a path by which content outside managed review reaches the agent. Fix: set syncClaudeAiSkills to false."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-56", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST02", nist_800_53 = "CM-7", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "syncClaudeAiSkills"), "__COND__", local.cond_false), "__FIX__", "Set syncClaudeAiSkills to false."), "__ABSENT__", local.absent_skip_local), "__ABSENT_REASON__", "syncClaudeAiSkills is not set; skills from the claude.ai account may sync into sessions. Set it to false.")
}

control "claude_ai_plugin_sync_disabled" {
  title       = "Plugins do not sync from claude.ai"
  description = "syncClaudeAiPlugins pulls plugins from the claude.ai account into local sessions, bypassing marketplace controls. Fix: set syncClaudeAiPlugins to false."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-57", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST02", nist_800_53 = "CM-7", anthropic_profile = "hipaa" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "syncClaudeAiPlugins"), "__COND__", local.cond_false), "__FIX__", "Set syncClaudeAiPlugins to false."), "__ABSENT__", local.absent_skip_local), "__ABSENT_REASON__", "syncClaudeAiPlugins is not set; plugins from the claude.ai account may sync into sessions. Set it to false.")
}

control "cross_session_inbound_refused" {
  title       = "Inbound messages from other sessions are refused"
  description = "crossSessionInbound refuse stops other Claude sessions from sending this one instructions, an injection path that needs no file. Fix: set crossSessionInbound to \"refuse\"."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "HD-58", agentreach_class = "needs_validation", owasp_agentic = "ASI07", nist_800_53 = "SC-7", anthropic_profile = "hipaa", mitre_atlas = "AML.T0051.001" })
  param "deployment" { default = var.deployment }
  sql = replace(replace(replace(replace(replace(local.scalar_sql, "__KEY__", "crossSessionInbound"), "__COND__", "value = '\"refuse\"'::jsonb"), "__FIX__", "Set crossSessionInbound to \"refuse\"."), "__ABSENT__", local.absent_info), "__ABSENT_REASON__", "crossSessionInbound is not set; other sessions can message this one. Set it to \"refuse\".")
}

control "home_directory_not_a_project" {
  title       = "Claude Code is not run from the home directory"
  description = "A session started in $HOME has the whole home directory as its working directory: every credential file is inside the boundary, and trust is held for the session only so the prompt reappears and is accepted by habit. Fix: start sessions from a project directory."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "HD-59", agentreach_class = "needs_validation", owasp_agentic = "ASI03", nist_800_53 = "AC-6", mitre_atlas = "AML.T0083" })
  sql = <<-EOQ
    select
      a.agent as resource,
      case when exists (select 1 from (select * from agentreach_project where agent = 'claude_code') p where p.project_dir = regexp_replace(a.config_dir, '/\.claude$', '')) then 'alarm' else 'ok' end as status,
      case
        when exists (select 1 from (select * from agentreach_project where agent = 'claude_code') p where p.project_dir = regexp_replace(a.config_dir, '/\.claude$', ''))
          then 'Claude Code has been started in ' || regexp_replace(a.config_dir, '/\.claude$', '') || ', which makes every file under the home directory part of the working tree. Start sessions from a project directory.'
        else 'No session has been started from the home directory.'
      end as reason,
      a.agent
    from (select * from agentreach_agent where agent = 'claude_code') a;
  EOQ
}
