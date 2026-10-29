# Supply chain: plugins, marketplaces and skills. The atoms behind OWASP
# ASI04, the Agentic Skills Top 10 (AST02, AST03, AST05, AST06, AST07, AST09)
# and How to Harden 2.2. Reads agentreach_plugin, agentreach_marketplace and
# agentreach_instruction_file (kind = skill).

benchmark "supply_chain" {
  title       = "8. Plugins, marketplaces and skills"
  description = "What the agent installed from outside: whether each marketplace is allowlisted and official, whether each plugin is pinned to a release, whether skills fetch external instructions, and whether any of it is writable by someone other than the owner."
  children = [
    control.marketplaces_inventoried,
    control.marketplaces_in_allowlist,
    control.marketplaces_not_auto_updating,
    control.plugins_inventoried,
    control.plugins_pinned_to_release,
    control.plugins_owner_writable,
    control.plugins_with_hooks_reviewed,
    control.plugins_with_mcp_reviewed,
    control.skills_inventoried,
    control.skills_no_external_urls,
    control.skills_owner_writable,
    control.skills_third_party_reviewed,
    control.skills_no_hidden_content,
  ]
  tags = merge(local.common_tags, { group = "supply_chain" })
}

control "marketplaces_inventoried" {
  title       = "Every plugin marketplace is known"
  description = "An inventory of marketplace sources is the first governance step: each one is a code source the agent trusts. Rows are informational; official marketplaces pass."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "SC-01", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST09", hth = "2.2", nist_800_53 = "CM-8", csa_mcp = "L1", mitre_atlas = "AML.M0028" })
  sql = <<-EOQ
    select
      name as resource,
      case when official then 'ok' else 'info' end as status,
      case
        when official then name || ' is the official Anthropic marketplace (' || source_repo || ').'
        else name || ' is a ' || source_type || ' marketplace from ' || source_repo || case when install_location_exists then ', cloned at ' || install_location else ', not cloned' end || '. Confirm it belongs on this machine.'
      end as reason,
      source_type, agent
    from (select * from agentreach_marketplace where agent = 'claude_code') agentreach_marketplace
    order by official desc, name;
  EOQ
}

control "marketplaces_in_allowlist" {
  title       = "Every marketplace is in the strict allowlist"
  description = "strictKnownMarketplaces is the policy that decides which sources may be added. A marketplace outside it was added before the policy or in spite of it. With no policy at all, every marketplace is unrestricted. Fix: add the reviewed sources to strictKnownMarketplaces in managed settings and remove the rest."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "SC-02", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST02", hth = "2.2", nist_800_53 = "CM-7", anthropic_profile = "lax,strict,hipaa", mitre_atlas = "AML.T0104" })
  param "deployment" { default = var.deployment }
  sql = <<-EOQ
    select
      name as resource,
      case
        when in_strict_allowlist then 'ok'
        when in_strict_allowlist is null and $1 = 'local' then 'info'
        else 'alarm'
      end as status,
      case
        when in_strict_allowlist then name || ' is in strictKnownMarketplaces.'
        when in_strict_allowlist is null then name || ' (' || source_repo || ') is unrestricted: no strictKnownMarketplaces policy exists' || case when $1 = 'local' then ', and a local deployment has no administrator to set one.' else '. Set one in managed settings.' end
        else name || ' (' || source_repo || ') is not in strictKnownMarketplaces but is still registered. Remove it or add it to the policy.'
      end as reason,
      source_type, $1 as deployment, agent
    from (select * from agentreach_marketplace where agent = 'claude_code') agentreach_marketplace
    order by name;
  EOQ
}

control "marketplaces_not_auto_updating" {
  title       = "Marketplaces do not auto-update"
  description = "A marketplace with autoUpdate pulls new plugin code on its own schedule, so a compromised upstream becomes active without anyone installing anything. Fix: remove autoUpdate from the marketplace entry and update by hand after review."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "SC-03", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST07", nist_800_53 = "SI-7", csa_mcp = "3.5", mitre_atlas = "AML.T0104" })
  sql = <<-EOQ
    select
      name as resource,
      -- With no autoUpdate entry, claude-plugins-official and most official
      -- Anthropic marketplaces auto-update; third-party ones do not
      -- (settings-reference, extraKnownMarketplaces).
      case when coalesce(auto_update, official) then 'alarm' else 'ok' end as status,
      case
        when auto_update then name || ' (' || source_repo || ') auto-updates, so upstream changes land without review. Turn autoUpdate off and update deliberately.'
        when auto_update is null and official then name || ' (' || source_repo || ') auto-updates by default: official marketplaces do unless autoUpdate is false. Set autoUpdate to false for it and update deliberately.'
        else name || ' does not auto-update.'
      end as reason,
      source_type, host, agent
    from (select * from agentreach_marketplace where agent = 'claude_code') agentreach_marketplace
    order by name;
  EOQ
}

control "plugins_inventoried" {
  title       = "Every installed plugin is known"
  description = "Each installed plugin can ship hooks, MCP servers, skills, agents, commands and instruction files that the agent obeys. The inventory is the base for every other plugin control. Enabled plugins are listed as info; disabled ones pass."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "SC-04", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST09", hth = "2.2", nist_800_53 = "CM-8", csa_mcp = "L1", mitre_atlas = "AML.M0028" })
  sql = <<-EOQ
    select
      full_name || ' [' || scope || coalesce(':' || nullif(project_dir, ''), '') || ']' as resource,
      case when enabled is false then 'ok' else 'info' end as status,
      full_name || ' v' || coalesce(nullif(version, ''), '?') || ' is ' || case when enabled then 'enabled' when enabled is null then 'installed with no enabledPlugins decision, so it follows its defaultEnabled value and loads unless the manifest says otherwise,' else 'disabled' end
        || ' at ' || scope || ' scope; ships ' || skill_count || ' skill(s), ' || agent_count || ' agent(s), ' || command_count || ' command(s)'
        || case when has_hooks then ', hooks' else '' end || case when has_mcp then ', MCP servers' else '' end || case when has_instruction_file then ', a CLAUDE.md' else '' end || '.' as reason,
      scope, marketplace, host, agent
    from (select * from agentreach_plugin where agent = 'claude_code') agentreach_plugin
    order by enabled desc nulls last, full_name;
  EOQ
}

control "plugins_pinned_to_release" {
  title       = "Enabled plugins are pinned to a release, not a floating commit"
  description = "A plugin whose version is a commit hash moves whenever the marketplace clone moves; a release version stays put until someone changes it. Fix: set the plugin's version in the marketplace entry, or use a marketplace that publishes releases."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "SC-05", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST07", hth = "2.2", nist_800_53 = "SI-7", csa_mcp = "3.5", mitre_atlas = "AML.T0104" })
  # agentreach_plugin.pinned: null when no version is recorded, false for a commit
  # or a prefix of the recorded commit, true for a release (incl. CalVer).
  sql = <<-EOQ
    with p as (
      select *, pinned as release
      from (select * from agentreach_plugin where agent = 'claude_code') agentreach_plugin
    )
    select
      full_name || ' [' || scope || coalesce(':' || nullif(project_dir, ''), '') || ']' as resource,
      case
        when enabled is false then 'skip'
        when release then 'ok'
        when release is null then 'info'
        else 'alarm'
      end as status,
      case
        when enabled is false then full_name || ' is disabled.'
        when release then full_name || ' is pinned to version ' || version || '.'
        when release is null then full_name || ' records no usable version (' || coalesce(nullif(version, ''), 'none') || '), so agentreach cannot tell whether it floats.'
        else full_name || ' floats at commit ' || left(coalesce(nullif(git_commit_sha, ''), version), 12) || '; the next marketplace update changes what runs. Pin it to a release.'
      end as reason,
      scope, marketplace, host, agent
    from p
    order by full_name;
  EOQ
}

control "plugins_owner_writable" {
  title       = "Installed plugin directories are writable only by their owner"
  description = "A plugin directory writable by group or others lets any local process edit the hooks, skills and MCP definitions the agent loads next session. Fix: chmod the install path to owner-write."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "SC-06", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST07", nist_800_53 = "AC-3", mitre_atlas = "AML.T0081" })
  sql = <<-EOQ
    select
      full_name || ' [' || scope || ']' as resource,
      case when not install_path_exists then 'skip' when writable_by = 'owner' then 'ok' else 'alarm' end as status,
      case
        when not install_path_exists then full_name || ' install path ' || install_path || ' does not exist.'
        when writable_by = 'owner' then install_path || ' is owner-writable.'
        else install_path || ' is writable by ' || writable_by || '. Any local process can change what this plugin makes the agent do. Restrict it to owner-write.'
      end as reason,
      scope, marketplace, agent
    from (select * from agentreach_plugin where agent = 'claude_code') agentreach_plugin
    order by full_name;
  EOQ
}

control "plugins_with_hooks_reviewed" {
  title       = "Enabled plugins that ship hooks are reviewed"
  description = "A plugin hook runs a command on every matching event, with your privileges, outside the sandbox. Each enabled plugin that ships hooks needs a reviewer who read them. Rows are informational."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "SC-07", agentreach_class = "needs_validation", owasp_agentic = "ASI05", owasp_skills = "AST03", hth = "2.2", nist_800_53 = "CM-7", mitre_atlas = "AML.T0053" })
  sql = <<-EOQ
    select
      full_name || ' [' || scope || ']' as resource,
      case when has_hooks and enabled is distinct from false then 'info' else 'ok' end as status,
      case
        when has_hooks and enabled is distinct from false then full_name || ' is enabled and ships hooks (' || install_path || '/hooks/hooks.json). Read them; they run outside the sandbox on every matching event.'
        when has_hooks then full_name || ' ships hooks but is disabled.'
        else full_name || ' ships no hooks.'
      end as reason,
      scope, marketplace, agent
    from (select * from agentreach_plugin where agent = 'claude_code') agentreach_plugin
    order by has_hooks desc, full_name;
  EOQ
}

control "plugins_with_mcp_reviewed" {
  title       = "Enabled plugins that ship MCP servers are reviewed"
  description = "A plugin can add MCP servers that never appear in .mcp.json, so reviewing the repository does not show them. Each enabled plugin that ships servers needs a reviewer who read the launch command. Rows are informational."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "SC-08", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_mcp = "MCP09", owasp_skills = "AST03", hth = "2.1", nist_800_53 = "CM-7", csa_mcp = "L1", mitre_atlas = "AML.T0104" })
  sql = <<-EOQ
    select
      full_name || ' [' || scope || ']' as resource,
      case when has_mcp and enabled is distinct from false then 'info' else 'ok' end as status,
      case
        when has_mcp and enabled is distinct from false then full_name || ' is enabled and ships MCP servers that do not appear in any .mcp.json. Read the launch commands in ' || install_path || '.'
        when has_mcp then full_name || ' ships MCP servers but is disabled.'
        else full_name || ' ships no MCP servers.'
      end as reason,
      scope, marketplace, agent
    from (select * from agentreach_plugin where agent = 'claude_code') agentreach_plugin
    order by has_mcp desc, full_name;
  EOQ
}

control "skills_inventoried" {
  title       = "Every skill the agent can load is known"
  description = "Skills are instructions the agent follows when it decides they apply; each is an instruction source. The inventory counts them by scope and origin. Rows are informational."
  severity    = "low"
  tags = merge(local.common_tags, { agentreach = "SC-09", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST09", nist_800_53 = "CM-8", mitre_atlas = "AML.M0028" })
  sql = <<-EOQ
    select
      a.agent || ' skills: ' || i.scope || coalesce(' plugin ' || nullif(i.plugin_name, ''), '') as resource,
      'info' as status,
      count(*) || ' skill file(s) at ' || i.scope || ' scope' || coalesce(' from plugin ' || nullif(i.plugin_name, ''), '') || ', ' || sum(case when i.third_party then 1 else 0 end) || ' third party, ' || sum(case when i.external_url_count > 0 then 1 else 0 end) || ' with external URLs.' as reason,
      i.scope, a.agent
    from (select * from agentreach_instruction_file where agent = 'claude_code') i join (select * from agentreach_agent where agent = 'claude_code') a on a.agent = i.agent
    where i.kind = 'skill'
    group by a.agent, i.scope, i.plugin_name
    order by i.scope, i.plugin_name;
  EOQ
}

control "skills_no_external_urls" {
  title       = "Skills do not point the agent at external instructions"
  description = "A skill that tells the agent to read a URL makes that page part of its instructions, and the page can change after review. Fix: inline the referenced content into the skill, or pin and review the URL."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "SC-10", agentreach_class = "needs_validation", owasp_agentic = "ASI01", owasp_skills = "AST05", nist_800_53 = "SI-7", mitre_atlas = "AML.T0051.001" })
  sql = <<-EOQ
    select
      path as resource,
      case when plugin_enabled is false then 'skip' when external_url_count = 0 then 'ok' else 'alarm' end as status,
      case
        when plugin_enabled is false then regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' ships with disabled plugin ' || plugin_name || ' and does not load.'
        when external_url_count = 0 then regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' references no external URL.'
        else regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' references ' || external_url_count || ' external URL(s)' || coalesce(' (plugin ' || nullif(plugin_name, '') || ')', '') || '. Content fetched from them becomes instructions. Inline it or review and pin it.'
      end as reason,
      scope, host, agent
    from (select * from agentreach_instruction_file where agent = 'claude_code') agentreach_instruction_file
    where kind = 'skill'
    order by external_url_count desc, path;
  EOQ
}

control "skills_owner_writable" {
  title       = "Skill files are writable only by their owner"
  description = "Skills hot-reload: a skill file edited mid-session changes what the agent does next without a restart. A file writable by group or others lets any local process do that. Fix: chmod skill files and directories to owner-write."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "SC-11", agentreach_class = "needs_validation", owasp_agentic = "ASI06", owasp_skills = "AST07", nist_800_53 = "AC-3", mitre_atlas = "AML.T0080" })
  sql = <<-EOQ
    select
      path as resource,
      case when plugin_enabled is false then 'skip' when writable_by = 'owner' then 'ok' else 'alarm' end as status,
      case
        when plugin_enabled is false then regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' ships with disabled plugin ' || plugin_name || ' and does not load.'
        when writable_by = 'owner' then regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' is owner-writable.'
        else regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' is writable by ' || writable_by || '. Restrict it to owner-write.'
      end as reason,
      scope, host, agent
    from (select * from agentreach_instruction_file where agent = 'claude_code') agentreach_instruction_file
    where kind = 'skill'
    order by path;
  EOQ
}

control "skills_third_party_reviewed" {
  title       = "Third-party skills are reviewed"
  description = "A skill a plugin shipped, or whose last commit is by someone outside the repository's identities, is content the user did not write. Each needs a reviewer who read it. Rows are informational."
  severity    = "medium"
  tags = merge(local.common_tags, { agentreach = "SC-12", agentreach_class = "needs_validation", owasp_agentic = "ASI04", owasp_skills = "AST01", nist_800_53 = "SI-7", mitre_atlas = "AML.T0110" })
  sql = <<-EOQ
    select
      path as resource,
      case when plugin_enabled is false then 'skip' when third_party then 'info' else 'ok' end as status,
      case
        when plugin_enabled is false then regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' ships with disabled plugin ' || plugin_name || ' and does not load.'
        when third_party then regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' is third party' || coalesce(' (plugin ' || nullif(plugin_name, '') || ')', coalesce(' (last commit by ' || nullif(git_last_author, '') || ')', '')) || '. Read it before the agent does.'
        else regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' was written by the repository owner.'
      end as reason,
      scope, host, agent
    from (select * from agentreach_instruction_file where agent = 'claude_code') agentreach_instruction_file
    where kind = 'skill'
    order by third_party desc, path;
  EOQ
}

control "skills_no_hidden_content" {
  title       = "Skills carry no hidden Unicode or HTML comments"
  description = "Zero-width characters and HTML comments are invisible in a rendered skill but the model reads them, which is how a published skill hides an instruction from its reviewer. Fix: strip them and re-review."
  severity    = "high"
  tags = merge(local.common_tags, { agentreach = "SC-13", agentreach_class = "needs_validation", owasp_agentic = "ASI01", owasp_skills = "AST04", nist_800_53 = "SI-10", mitre_atlas = "AML.T0051.001" })
  sql = <<-EOQ
    select
      path as resource,
      case when plugin_enabled is false then 'skip' when hidden_unicode_count = 0 and html_comment_count = 0 then 'ok' else 'alarm' end as status,
      case
        when plugin_enabled is false then regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' ships with disabled plugin ' || plugin_name || ' and does not load.'
        when hidden_unicode_count = 0 and html_comment_count = 0 then regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' has no hidden content.'
        else regexp_replace(path, '^/Users/[^/]+|^/home/[^/]+', '~') || ' has ' || hidden_unicode_count || ' hidden Unicode character(s) and ' || html_comment_count || ' HTML comment(s). Strip them and read what they said.'
      end as reason,
      scope, host, agent
    from (select * from agentreach_instruction_file where agent = 'claude_code') agentreach_instruction_file
    where kind = 'skill'
    order by (hidden_unicode_count + html_comment_count) desc, path;
  EOQ
}
