benchmark "reachability" {
  title       = "6. Reachability"
  description = "What the agent's shell commands and Read tool can actually open or connect to, measured by inert probes (open for read and discard, dial and disconnect). These are effects, not configuration: a rule that is not enforced does not count."
  children = [
    control.sensitive_files_denied_in_sandbox,
    control.env_files_not_readable,
    control.local_services_restricted,
    control.docker_socket_unreachable,
    control.agent_credentials_of_other_agents_unreachable,
    control.local_services_as_exits,
  ]
  tags = merge(local.common_tags, { group = "reachability" })
}

control "sensitive_files_denied_in_sandbox" {
  title       = "Sensitive files are denied for both shell commands and the Read tool"
  description = "The sandbox denyRead list governs shell commands; the permissions deny list (Read(//path)) governs the Read tool. A file needs both to be unreachable. This control covers every sensitive category except .env files, which have their own control."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "RC-01"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM02:2025 Sensitive Information Disclosure"
    owasp_agentic              = "ASI03 Identity and Privilege Abuse"
    cis_controls_v8            = "3.3"
    aws_coding_agent_framework = "R002"
    owasp_agent_cheatsheet     = "8"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    select
      f.path as resource,
      case
        when f.reachable_via_bash or f.reachable_via_read_tool then 'alarm'
        else 'ok'
      end as status,
      case
        when f.reachable_via_bash and f.reachable_via_read_tool and not a.sandbox_enabled
          then f.path || ' (' || f.category || ') is open to shell commands and the Read tool. Enable the sandbox, add the path to sandbox.filesystem.denyRead, and add Read(//' || ltrim(f.path, '/') || case when f.is_dir then '/**' else '' end || ') to permissions.deny.'
        when f.reachable_via_bash and f.reachable_via_read_tool
          then f.path || ' (' || f.category || ') is open to shell commands and the Read tool. Add it to sandbox.filesystem.denyRead and add Read(//' || ltrim(f.path, '/') || case when f.is_dir then '/**' else '' end || ') to permissions.deny.'
        when f.reachable_via_bash
          then f.path || ' (' || f.category || ') is blocked for the Read tool but open to shell commands. Add it to sandbox.filesystem.denyRead' || case when a.sandbox_enabled then '.' else ' and enable the sandbox.' end
        when f.reachable_via_read_tool
          then f.path || ' (' || f.category || ') is blocked for shell commands but open to the Read tool. Add Read(//' || ltrim(f.path, '/') || case when f.is_dir then '/**' else '' end || ') to permissions.deny.'
        else f.path || ' is blocked for shell commands and the Read tool.'
      end as reason,
      f.category,
      f.project_dir
    from (select * from agentreach_reach_file where agent = 'claude_code') f
    join (select * from agentreach_agent where agent = 'claude_code') a on a.agent = f.agent
    where f.exists and f.category <> 'env_file';
  EOQ
}

control "env_files_not_readable" {
  title       = ".env files are not readable by the agent"
  description = "Project .env files are the most common place secrets live and the first thing an injected instruction asks for. The agent's own working directory is readable by design, so .env needs an explicit deny on both layers. Fix: add .env and .env.* to sandbox.filesystem.denyRead and Read(./.env*) to permissions.deny in the project's .claude/settings.json."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "RC-02"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM02:2025 Sensitive Information Disclosure"
    owasp_agentic              = "ASI03 Identity and Privilege Abuse"
    cis_controls_v8            = "3.3"
    aws_coding_agent_framework = "R002"
    owasp_agent_cheatsheet     = "8"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    select
      f.path as resource,
      case
        when f.reachable_via_bash or f.reachable_via_read_tool then 'alarm'
        else 'ok'
      end as status,
      case
        when f.reachable_via_bash or f.reachable_via_read_tool
          then f.path || ' is readable by the agent (' ||
            concat_ws(' and ',
              case when f.reachable_via_bash then 'shell commands' end,
              case when f.reachable_via_read_tool then 'the Read tool' end)
            || '). Add .env* to sandbox.filesystem.denyRead and Read(./.env*) to permissions.deny in ' || coalesce(nullif(f.project_dir, ''), 'the project') || '/.claude/settings.json'
            || case when a.sandbox_enabled then '.' else ', and enable the sandbox.' end
        else f.path || ' is blocked for shell commands and the Read tool.'
      end as reason,
      f.category,
      f.project_dir
    from (select * from agentreach_reach_file where agent = 'claude_code') f
    join (select * from agentreach_agent where agent = 'claude_code') a on a.agent = f.agent
    where f.exists and f.category = 'env_file';
  EOQ
}

control "local_services_restricted" {
  title       = "Local network services are not reachable from shell commands"
  description = "Databases, admin UIs, LLM servers and dev proxies listening on localhost are reachable by anything the agent runs unless the sandbox blocks them. They are both a data source and a pivot. Fix: enable the sandbox; local ports are then blocked unless listed in sandbox.network.allowedDomains or an allowLocalBinding equivalent."
  severity    = "medium"
  tags = merge(local.common_tags, {
    agentreach                       = "RC-03"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI02 Tool Misuse"
    cis_controls_v8            = "12.2"
    aws_coding_agent_framework = "R005"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    -- agentreach_reach_host.approval (plugin approval.go): what a shell command
    -- connecting here needs. A port no rule allows is an unlisted host and
    -- is decided by the permission mode unless strictAllowlist refuses it
    -- (sandboxing, "Hostnames that resolve to local addresses").
    select
      target as resource,
      case
        when not coalesce(reachable, false) then 'ok'
        when approval = 'none' then 'alarm'
        when approval in ('prompt', 'classifier') then 'info'
        when approval = 'denied' then 'ok'
        else 'skip'
      end as status,
      case
        when not coalesce(reachable, false) then target || ' (' || coalesce(nullif(service, ''), 'unknown service') || coalesce(', ' || nullif(process_name, ''), '') || ')' || ' did not accept a connection.'
        when approval = 'none'
          then target || ' (' || coalesce(nullif(service, ''), 'unknown service') || coalesce(', ' || nullif(process_name, ''), '') || ')' || ' accepts connections and a shell command reaches it with no approval'
            || case when not sandbox_enabled then ': the sandbox is off.' when allowed_by_sandbox then ': ' || coalesce(nullif(sandbox_rule, ''), 'a sandbox rule') || ' allows it.' else '.' end
            || ' Enable the sandbox and do not list the port in sandbox.network.allowedDomains or allowLocalBinding unless the project needs it.'
        when approval = 'prompt' then target || ' (' || coalesce(nullif(service, ''), 'unknown service') || coalesce(', ' || nullif(process_name, ''), '') || ')' || ' accepts connections; a shell command reaches it only after you approve it. To refuse it without asking, enable the sandbox, leave it out of the allow rules and set sandbox.network.strictAllowlist (and allowUnsandboxedCommands false).'
        when approval = 'classifier' then target || ' (' || coalesce(nullif(service, ''), 'unknown service') || coalesce(', ' || nullif(process_name, ''), '') || ')' || ' accepts connections; auto mode''s classifier, not you, decides whether a shell command reaches it. To refuse it, set sandbox.network.strictAllowlist and allowUnsandboxedCommands false.'
        when approval = 'denied' then target || ' (' || coalesce(nullif(service, ''), 'unknown service') || coalesce(', ' || nullif(process_name, ''), '') || ')' || ' accepts connections, but the sandbox refuses it to shell commands in every mode.'
        else 'Not assessed: the permission mode is unknown, so agentreach cannot tell what a connection to ' || target || ' needs; see AG-02.'
      end as reason,
      service,
      host,
      agent
    from (select * from agentreach_reach_host where agent = 'claude_code') agentreach_reach_host
    where kind = 'tcp';
  EOQ
}

control "docker_socket_unreachable" {
  title       = "The Docker socket is not reachable from shell commands"
  description = "Write access to docker.sock is root on the host: a container with the host filesystem mounted is one command away. Fix: do not add the socket to sandbox.network.allowUnixSockets, enable the sandbox, and prefer a rootless or remote Docker context for agent sessions."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "RC-04"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI05 Unexpected Code Execution"
    cis_controls_v8            = "5.4"
    aws_coding_agent_framework = "R005"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    -- agentreach_reach_host.approval (plugin approval.go): what a shell command
    -- connecting here needs. A port no rule allows is an unlisted host and
    -- is decided by the permission mode unless strictAllowlist refuses it
    -- (sandboxing, "Hostnames that resolve to local addresses").
    select
      target as resource,
      case
        when not coalesce(reachable, false) then 'ok'
        when approval = 'none' then 'alarm'
        when approval in ('prompt', 'classifier') then 'info'
        when approval = 'denied' then 'ok'
        else 'skip'
      end as status,
      case
        when not coalesce(reachable, false) then target || ' did not accept a connection.'
        when approval = 'none'
          then target || ' accepts connections and a shell command reaches it with no approval'
            || case when not sandbox_enabled then ': the sandbox is off.' when allowed_by_sandbox then ': ' || coalesce(nullif(sandbox_rule, ''), 'a sandbox rule') || ' allows it.' else '.' end
            || ' Enable the sandbox and leave the socket out of sandbox.network.allowUnixSockets; this is root on the host.'
        when approval = 'prompt' then target || ' accepts connections; a shell command reaches it only after you approve it. To refuse it without asking, enable the sandbox, leave it out of the allow rules and set sandbox.network.strictAllowlist (and allowUnsandboxedCommands false).'
        when approval = 'classifier' then target || ' accepts connections; auto mode''s classifier, not you, decides whether a shell command reaches it. To refuse it, set sandbox.network.strictAllowlist and allowUnsandboxedCommands false.'
        when approval = 'denied' then target || ' accepts connections, but the sandbox refuses it to shell commands in every mode.'
        else 'Not assessed: the permission mode is unknown, so agentreach cannot tell what a connection to ' || target || ' needs; see AG-02.'
      end as reason,
      
      host,
      agent
    from (select * from agentreach_reach_host where agent = 'claude_code') agentreach_reach_host
    where kind = 'unix_socket'
      and (service in ('docker', 'docker-desktop', 'colima', 'orbstack', 'podman') or target like '%docker.sock');
  EOQ
}

control "agent_credentials_of_other_agents_unreachable" {
  title       = "Other agents' credential stores are not readable"
  description = "OAuth tokens and API keys for Claude Code, Codex, Cursor, Gemini CLI, GitHub Copilot and friends live in predictable home-directory paths. One agent reading another's token is lateral movement between assistants, and reading its own token is exfiltration-ready. Fix: add each store to sandbox.filesystem.denyRead and Read(//path) to permissions.deny."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "RC-05"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM02:2025 Sensitive Information Disclosure"
    owasp_agentic              = "ASI03 Identity and Privilege Abuse"
    cis_controls_v8            = "3.3"
    aws_coding_agent_framework = "R002"
    owasp_agent_cheatsheet     = "8"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    select
      f.path as resource,
      case when f.reachable_via_bash or f.reachable_via_read_tool then 'alarm' else 'ok' end as status,
      case
        when f.reachable_via_bash or f.reachable_via_read_tool
          then f.path || ' (' || f.description || ') is readable by the agent. Add it to sandbox.filesystem.denyRead and Read(//' || ltrim(f.path, '/') || case when f.is_dir then '/**' else '' end || ') to permissions.deny'
            || case when a.sandbox_enabled then '.' else ', and enable the sandbox.' end
        else f.path || ' is blocked.'
      end as reason,
      f.category,
      f.agent
    from (select * from agentreach_reach_file where agent = 'claude_code') f
    join (select * from agentreach_agent where agent = 'claude_code') a on a.agent = f.agent
    where f.exists and f.category = 'agent_credential';
  EOQ
}

control "local_services_as_exits" {
  title       = "Reachable local services are not exit channels for the agent"
  description = "A database, message broker, model server or container daemon listening on loopback is somewhere an injected instruction can write data to, not just read from: insert into a table, publish to a topic, start a container that phones home. Each reachable well-known service on loopback counts as an exit channel in the attack-path count. Fix: enable the sandbox, which blocks local ports by default, and add only the ports a project needs to sandbox.network.allowedDomains."
  severity    = "medium"
  tags = merge(local.common_tags, {
    agentreach                       = "RC-06"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM06:2025 Excessive Agency"
    owasp_agentic              = "ASI02 Tool Misuse"
    cis_controls_v8            = "12.2"
    aws_coding_agent_framework = "R005"
    owasp_agent_cheatsheet     = "1"
    knostic_threat_model       = "2"
  })

  sql = <<-EOQ
    -- agentreach_reach_host.approval (plugin approval.go): what a shell command
    -- connecting here needs. A port no rule allows is an unlisted host and
    -- is decided by the permission mode unless strictAllowlist refuses it
    -- (sandboxing, "Hostnames that resolve to local addresses").
    select
      target as resource,
      case
        when not coalesce(reachable, false) then 'ok'
        when approval = 'none' then 'alarm'
        when approval in ('prompt', 'classifier') then 'info'
        when approval = 'denied' then 'ok'
        else 'skip'
      end as status,
      case
        when not coalesce(reachable, false) then coalesce(nullif(service, ''), 'service') || ' at ' || target || coalesce(' (' || nullif(process_name, '') || ')', '') || ' did not accept a connection.'
        when approval = 'none'
          then coalesce(nullif(service, ''), 'service') || ' at ' || target || coalesce(' (' || nullif(process_name, '') || ')', '') || ' accepts connections and a shell command reaches it with no approval'
            || case when not sandbox_enabled then ': the sandbox is off.' when allowed_by_sandbox then ': ' || coalesce(nullif(sandbox_rule, ''), 'a sandbox rule') || ' allows it.' else '.' end
            || ' Anything the agent runs can hand it data. Enable the sandbox to close every local port by default.'
        when approval = 'prompt' then coalesce(nullif(service, ''), 'service') || ' at ' || target || coalesce(' (' || nullif(process_name, '') || ')', '') || ' accepts connections; a shell command reaches it only after you approve it. To refuse it without asking, enable the sandbox, leave it out of the allow rules and set sandbox.network.strictAllowlist (and allowUnsandboxedCommands false).'
        when approval = 'classifier' then coalesce(nullif(service, ''), 'service') || ' at ' || target || coalesce(' (' || nullif(process_name, '') || ')', '') || ' accepts connections; auto mode''s classifier, not you, decides whether a shell command reaches it. To refuse it, set sandbox.network.strictAllowlist and allowUnsandboxedCommands false.'
        when approval = 'denied' then coalesce(nullif(service, ''), 'service') || ' at ' || target || coalesce(' (' || nullif(process_name, '') || ')', '') || ' accepts connections, but the sandbox refuses it to shell commands in every mode.'
        else 'Not assessed: the permission mode is unknown, so agentreach cannot tell what a connection to ' || target || ' needs; see AG-02.'
      end as reason,
      service,
      kind,
      host,
      agent
    from (select * from agentreach_reach_host where agent = 'claude_code') agentreach_reach_host
    where (kind = 'tcp' and loopback
             and service in ('docker-tcp', 'docker-tls', 'kube-apiserver', 'kubelet', 'postgres', 'mysql', 'redis', 'ollama', 'kafka', 'prometheus'))
       or (kind = 'unix_socket' and service in ('docker', 'docker-desktop', 'colima', 'orbstack', 'podman'))
    order by kind, target;
  EOQ
}
