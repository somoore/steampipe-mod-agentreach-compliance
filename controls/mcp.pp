benchmark "mcp_servers" {
  title       = "4. MCP servers"
  description = "MCP servers are tool providers the agent trusts by configuration. Their launch commands run as you, their tool descriptions and results are untrusted content, and their configuration files are where credentials most often leak into plaintext."
  children = [
    control.no_inline_secrets,
    control.launchers_pinned,
    control.project_servers_explicitly_approved,
    control.remote_servers_https,
    control.launcher_types_allowed,
  ]
  tags = merge(local.common_tags, { group = "mcp_servers" })
}

control "no_inline_secrets" {
  title       = "MCP server configuration holds no inline credentials"
  description = "An API key written into the env, headers, args or url of an MCP server definition is a plaintext secret in a file the agent can read, and in .mcp.json it is a secret in the repository. The plugin never stores the value; it reports only that the shape matches a credential (a known token prefix, or a value of 16 or more characters under a key named like a key, token or secret). A $${VAR} reference is not a secret. Fix: replace the literal with a $${VAR} reference and set the variable in your shell or secret manager."
  severity    = "critical"
  tags = merge(local.common_tags, {
    agentreach                       = "MCP-01"
    agentreach_class                 = "agentreach_extension"
    owasp_llm_2025             = "LLM02:2025 Sensitive Information Disclosure"
    owasp_agentic              = "ASI03 Identity and Privilege Abuse"
    cis_controls_v8            = "3.3"
    aws_coding_agent_framework = "R002"
    owasp_agent_cheatsheet     = "8"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    with a as (select * from agentreach_agent where agent = 'claude_code'),
    m as (
      select m.* from (select * from agentreach_mcp_server where agent = 'claude_code') m
      join a on ${format(local.same_snapshot_sql, "m")}
      where not ${local.not_assessed_config_sql}
    )
    select a.agent as resource, 'skip' as status, ${local.not_assessed_reason_sql} as reason, null::text as scope, null::text as launcher_type, a.host, a.agent
    from a
    where ${local.not_assessed_config_sql}
    union all
    select a.agent, 'ok', 'No MCP server is configured.', null, null, a.host, a.agent
    from a
    where not ${local.not_assessed_config_sql}
      and not exists (select 1 from m where ${format(local.same_snapshot_sql, "m")})
    union all
    select
      m.name,
      case when m.has_inline_secret then 'alarm' else 'ok' end,
      case
        when m.has_inline_secret
          then m.name || ' in ' || m.source_path || ' has a value shaped like a credential. Replace it with a $${VAR} reference and set the variable outside the file.'
        else m.name || ' (' || m.scope || ') passes credentials by reference or needs none.'
      end,
      m.scope,
      m.launcher_type,
      m.host,
      m.agent
    from m
    order by host, resource;
  EOQ
}

control "launchers_pinned" {
  title       = "npx and uvx launchers name an exact package version"
  description = "An unpinned npx or uvx launcher resolves and runs the newest package on every start, so a registry compromise or a maintainer account takeover executes on your machine the next time the agent launches. Fix: pin the package (name@1.2.3) and bump it on purpose."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "MCP-02"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM03:2025 Supply Chain"
    owasp_agentic              = "ASI04 Agentic Supply Chain"
    cis_controls_v8            = "2.1"
    aws_coding_agent_framework = "R004"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "5"
  })

  param "require_pinned_launchers" {
    description = "Whether npx and uvx launchers must name an exact version."
    default     = var.require_pinned_launchers
  }

  sql = <<-EOQ
    select
      name as resource,
      case
        when not $1::bool then 'skip'
        when pinned then 'ok'
        else 'alarm'
      end as status,
      case
        when not $1::bool then 'Skipped: var.require_pinned_launchers is false.'
        when pinned then name || ' pins its ' || launcher_type || ' package version.'
        else name || ' starts with ' || launcher_type || ' and no exact version, so it runs whatever the registry serves next. Pin the package version in ' || source_path || '.'
      end as reason,
      scope,
      launcher_type,
      host
    from (select * from agentreach_mcp_server where agent = 'claude_code') agentreach_mcp_server
    -- pinned is null for launchers with no registry version, such as
    -- uv run <file.py>, node or a binary.
    where pinned is not null;
  EOQ
}

control "project_servers_explicitly_approved" {
  title       = "Project .mcp.json servers have a recorded approve or reject decision"
  description = "Servers declared in a repository's .mcp.json are a supply-chain input from whoever can push to that repo. The agent asks you to approve them on first use; a server with no decision recorded has never been reviewed. Fix: approve or reject each when prompted, or set enabledMcpjsonServers / disabledMcpjsonServers in the project's local settings."
  severity    = "medium"
  tags = merge(local.common_tags, {
    agentreach                       = "MCP-03"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM03:2025 Supply Chain"
    owasp_agentic              = "ASI04 Agentic Supply Chain"
    cis_controls_v8            = "2.1"
    aws_coding_agent_framework = "Controlled tool access using MCP"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "5"
  })

  sql = <<-EOQ
    select
      name as resource,
      case when enabled is null then 'alarm' else 'ok' end as status,
      case
        when enabled is null then name || ' in ' || source_path || ' has no approve/reject decision recorded. Review it and decide.'
        when enabled then name || ' is approved for ' || project_dir || '.'
        else name || ' is rejected for ' || project_dir || '.'
      end as reason,
      scope,
      project_dir
    from (select * from agentreach_mcp_server where agent = 'claude_code') agentreach_mcp_server
    where scope = 'project';
  EOQ
}

control "remote_servers_https" {
  title       = "Remote MCP servers use HTTPS or loopback"
  description = "A remote server reached over plain HTTP on a non-loopback address sends tool calls, results and any auth header in cleartext. Loopback (127.0.0.1, localhost, ::1) is exempt because it never leaves the host. Fix: switch the url to https:// or front the server with a TLS proxy."
  severity    = "medium"
  tags = merge(local.common_tags, {
    agentreach                       = "MCP-04"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM02:2025 Sensitive Information Disclosure"
    owasp_agentic              = "ASI02 Tool Misuse"
    cis_controls_v8            = "3.10"
    aws_coding_agent_framework = "R005"
    owasp_agent_cheatsheet     = "8"
    knostic_threat_model       = "5"
  })

  sql = <<-EOQ
    select
      name as resource,
      case
        when url ~* '^https://' then 'ok'
        when url ~* '^http://(127\.0\.0\.1|localhost|\[::1\])([:/]|$)' then 'ok'
        else 'alarm'
      end as status,
      case
        when url ~* '^https://' then name || ' uses TLS: ' || url
        when url ~* '^http://(127\.0\.0\.1|localhost|\[::1\])([:/]|$)' then name || ' is a loopback endpoint: ' || url
        else name || ' uses cleartext ' || url || '. Switch to https:// or front it with a TLS proxy.'
      end as reason,
      scope,
      transport
    from (select * from agentreach_mcp_server where agent = 'claude_code') agentreach_mcp_server
    where coalesce(url, '') <> '';
  EOQ
}

control "launcher_types_allowed" {
  title       = "MCP launcher types are on the allowed list"
  description = "Each launcher type carries a different trust story: a binary you installed, a node or python script in a path you own, a registry fetch (npx, uvx), a container, a shell one-liner, or a remote endpoint. Narrow var.allowed_mcp_launchers to the types your policy accepts."
  severity    = "low"
  tags = merge(local.common_tags, {
    agentreach                       = "MCP-05"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM03:2025 Supply Chain"
    owasp_agentic              = "ASI04 Agentic Supply Chain"
    cis_controls_v8            = "2.1"
    aws_coding_agent_framework = "Controlled tool access using MCP"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "5"
  })

  param "allowed_mcp_launchers" {
    description = "Launcher types an MCP server may use."
    default     = var.allowed_mcp_launchers
  }

  sql = <<-EOQ
    select
      name as resource,
      case
        when launcher_type in (select jsonb_array_elements_text($1::jsonb)) then 'ok'
        else 'alarm'
      end as status,
      case
        when launcher_type in (select jsonb_array_elements_text($1::jsonb))
          then name || ' launches via ' || launcher_type || '.'
        else name || ' launches via ' || launcher_type || ', which is not on the allowed list. Replace it or add the type to var.allowed_mcp_launchers.'
      end as reason,
      scope,
      launcher_type
    from (select * from agentreach_mcp_server where agent = 'claude_code') agentreach_mcp_server;
  EOQ
}
