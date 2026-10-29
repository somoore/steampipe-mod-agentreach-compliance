dashboard "agentreach_posture" {
  title         = "Coding Agent Security Posture"
  documentation = file("./docs/agentreach_posture.md")
  tags          = merge(local.common_tags, { type = "Dashboard" })

  input "host" {
    title = "Machine"
    type  = "select"
    width = 4
    query = query.agentreach_input_hosts
  }

  # ── Verdict ──────────────────────────────────────────────────────────
  container {
    card {
      width = 12
      icon  = "gpp_maybe"
      query = query.agentreach_card_verdict
      args  = { host = self.input.host.value }
    }
  }

  # ── Posture cards ────────────────────────────────────────────────────
  container {
    card {
      width = 2
      icon  = "key"
      query = query.agentreach_card_critical_targets
      args  = { host = self.input.host.value }
    }
    card {
      width = 2
      icon  = "warning"
      query = query.agentreach_card_untrusted_inputs
      args  = { host = self.input.host.value }
    }
    card {
      width = 2
      icon  = "cloud_upload"
      query = query.agentreach_card_exit_channels
      args  = { host = self.input.host.value }
    }
    card {
      width = 2
      icon  = "verified_user"
      query = query.agentreach_card_controls
      args  = { host = self.input.host.value }
    }
    card {
      width = 2
      icon  = "shield"
      query = query.agentreach_card_sandbox
      args  = { host = self.input.host.value }
    }
    card {
      width = 2
      icon  = "how_to_reg"
      query = query.agentreach_card_permission_mode
      args  = { host = self.input.host.value }
    }
  }

  # ── Agents discovered ────────────────────────────────────────────────
  container {
    table {
      title = "Coding agents and harnesses discovered on this machine (the controls judge Claude Code only)"
      width = 12
      query = query.agentreach_table_agents
      args  = { host = self.input.host.value }
    }
  }

  # ── Worst paths ──────────────────────────────────────────────────────
  container {
    table {
      title = "Worst attack paths on this machine: one row is one concrete thing that could happen"
      width = 12
      query = query.agentreach_table_worst_paths
      args  = { host = self.input.host.value }
    }
  }

  # ── One path, drawn ──────────────────────────────────────────────────
  container {
    title = "Follow one path"

    input "path_id" {
      title       = "Attack path (worst first)"
      type        = "select"
      width       = 12
      query       = query.agentreach_input_paths
      args        = { host = self.input.host.value }
    }

    graph {
      title     = "What happens, step by step. Red labels are the controls that would have stopped it."
      width     = 4
      direction = "top_down"

      node {
        base = node.agentreach_path_source_tampered
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      node {
        base = node.agentreach_path_source_plugin
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      node {
        base = node.agentreach_path_source_mcp
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      node {
        base = node.agentreach_path_source_hook
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      node {
        base = node.agentreach_path_source_web
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      node {
        base = node.agentreach_path_agent
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      node {
        base = node.agentreach_path_target
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      node {
        base = node.agentreach_path_exit
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      edge {
        base = edge.agentreach_path_obeys
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      edge {
        base = edge.agentreach_path_reads
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
      edge {
        base = edge.agentreach_path_sends
        args = { host = self.input.host.value, path_id = self.input.path_id.value }
      }
    }

    table {
      title = "This path, in plain words"
      width = 8
      query = query.agentreach_table_path_story
      args  = { host = self.input.host.value, path_id = self.input.path_id.value }
    }
  }

  # ── Cut one leg ──────────────────────────────────────────────────────
  container {
    table {
      title = "What to change first: fixes ranked by attack paths closed"
      width = 12
      query = query.agentreach_table_cut_one_leg
      args  = { host = self.input.host.value }
    }
  }

  # ── Detail tables ────────────────────────────────────────────────────
  container {
    table {
      title = "Private files the agent can read, by blast radius"
      width = 12
      query = query.agentreach_table_private_files
      args  = { host = self.input.host.value }
    }
  }
  container {
    table {
      title = "MCP servers with findings"
      width = 12
      query = query.agentreach_table_mcp_findings
      args  = { host = self.input.host.value }
    }
  }
  container {
    table {
      title = "Hooks that run outside the sandbox"
      width = 12
      query = query.agentreach_table_hooks
      args  = { host = self.input.host.value }
    }
  }
}

# ------------------------------------------------------------------
# Machine picker
# ------------------------------------------------------------------

query "agentreach_input_hosts" {
  sql = <<-EOQ
    select host as label, host as value
    from agentreach_agent
    where agent = 'claude_code'
    group by host
    order by host;
  EOQ
}

# ------------------------------------------------------------------
# Cards
# ------------------------------------------------------------------

query "agentreach_card_verdict" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql},
    ${local.leg_exits_sql},
    ${local.leg_paths_sql},
    a as (select * from agentreach_agent where agent = 'claude_code' and host = (select host from scope) limit 1),
    t1 as (
      select string_agg(distinct category_label, ', ' order by category_label) as labels, count(distinct path) as n
      from worst where tier = 1
    ),
    n as (
      select
        (select count(*) from untrusted) as sources,
        (select count(*) from worst) as pairs,
        (select count(*) from worst where approval = 'none') as open_pairs,
        (select count(*) from worst where approval = 'unknown') as unknown_pairs,
        (select count(*) from exits where approval = 'none' and kind = 'internet') as inet,
        (select count(*) from exits where approval = 'none' and kind = 'internet' and coalesce(project_dir, '') = '') as inet_machine,
        (select count(distinct project_dir) from exits where approval = 'none' and kind = 'internet' and coalesce(project_dir, '') <> '') as inet_projects
    )
    select
      'Verdict' as label,
      case
        when coalesce(jsonb_array_length(a.collect_errors), 0) > 0
          then 'Not fully assessed: ' || jsonb_array_length(a.collect_errors) || ' configuration source(s) could not be read, so everything below could be wrong either way. See AG-06.'
        when not a.probed
          then 'Not fully assessed: probes were off, so what the agent can reach is unknown. See AG-06.'
        when n.pairs = 0 then 'No untrusted content can reach a private file and an exit. Keep it that way.'
        when n.open_pairs > 0 and t1.n > 0 then
          'Content you did not write (' || n.sources || ' sources) can make Claude Code read your ' || t1.labels
          || ' and send them ' || case
               when n.inet_machine > 0 then 'to any host on the internet'
               when n.inet > 0 then 'to any host on the internet from sessions in ' || n.inet_projects || ' project(s) whose allow rules run network commands'
               else 'out through plugin hooks or MCP servers' end
          || ', and no step asks you first.'
        when n.open_pairs > 0 then
          'Content you did not write (' || n.sources || ' sources) can read ' || n.open_pairs || ' lower-tier file(s) and send them out with no step that asks you.'
        when n.unknown_pairs > 0 then
          'Not fully assessed: the permission mode is unknown, so agentreach cannot tell whether anything asks you before ' || n.unknown_pairs || ' private file(s) leave. See AG-02.'
        else
          'Content you did not write (' || n.sources || ' sources) can reach ' || n.pairs || ' private file(s), but each path waits for '
          || case when a.effective_permission_mode = 'auto' then 'auto mode''s classifier' else 'your approval' end || ' at some step, to read the file or to send it. That approval is all that stands in the way.'
      end as value,
      case
        when coalesce(jsonb_array_length(a.collect_errors), 0) > 0 or not a.probed then 'info'
        when n.open_pairs > 0 then 'alert'
        when n.pairs > 0 then 'info'
        else 'ok'
      end as type
    from a, n, t1;
  EOQ
}

query "agentreach_card_critical_targets" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql},
    ${local.leg_exits_sql},
    ${local.leg_paths_sql}
    select
      'Tier-1 secrets reachable' as label,
      count(distinct path) as value,
      case when count(*) > 0 then 'alert' else 'ok' end as type
    from worst
    where tier = 1;
  EOQ
}

query "agentreach_card_untrusted_inputs" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}
    select
      'Untrusted sources' as label,
      count(*) as value,
      case when count(*) > 0 then 'alert' else 'ok' end as type
    from untrusted;
  EOQ
}

query "agentreach_card_exit_channels" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_exits_sql}
    select
      'Exits with no prompt' as label,
      count(*) filter (where approval = 'none') as value,
      case when count(*) filter (where approval = 'none') > 0 then 'alert' when count(*) > 0 then 'info' else 'ok' end as type
    from exits;
  EOQ
}

query "agentreach_card_controls" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}, a as (select * from agentreach_agent where agent = 'claude_code' and host = (select host from scope) limit 1),
    c as (
      select
        (select sandbox_enforced from a)::int as sandbox,
        (select count(*) > 0 from (select * from agentreach_reach_file where agent = 'claude_code' and host = (select host from scope)) f, a where f.host = a.host and f.tier = 1 and f.exists and f.sandbox_deny_read_rule <> '' and a.sandbox_enforced)::int as deny_read,
        (select count(*) > 0 from (select * from agentreach_reach_file where agent = 'claude_code' and host = (select host from scope)) f, a where f.host = a.host and f.tier = 1 and f.exists and f.permission_deny_read_rule <> '')::int as read_deny
    )
    select
      'Controls in place' as label,
      (sandbox + deny_read + read_deny) || ' of 3' as value,
      case when sandbox + deny_read + read_deny = 3 then 'ok' when sandbox + deny_read + read_deny > 0 then 'info' else 'alert' end as type
    from c;
  EOQ
}

# ------------------------------------------------------------------
# Worst paths
# ------------------------------------------------------------------

query "agentreach_table_worst_paths" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql},
    ${local.leg_exits_sql},
    ${local.leg_paths_sql}
    select
      rank as "#",
      source_title || '  (' || source_detail || ')' || case when other_sources > 0 then '  +' || other_sources || ' more' else '' end as "Untrusted source",
      case kind_group
        when 'plugin_hook' then 'runs as a hook on every matching tool call'
        when 'mcp' then 'answers tool calls with text the agent acts on'
        when 'web_tool' then 'returns pages the agent reads'
        else 'is loaded into the context as instructions' end as "How it reaches the agent",
      'Claude Code runs a ' || via || case when not sandbox_enabled then ' (sandbox off)' else '' end as "Then",
      target_title || '  (' || description || ')' as "Reads",
      case when exit_kind = 'plugin_hooks' then exit_title || ' (they see it; whether they send it depends on their code)' else exit_title end as "Sends to",
      case approval when 'none' then 'nothing asks you' when 'classifier' then 'auto mode''s classifier' when 'prompt' then 'you, at a prompt' else 'unknown' end as "Approved by",
      concat_ws('; ',
        case when reachable_via_bash and not sandbox_enforced then 'enforce the sandbox' end,
        case when reachable_via_bash then 'denyRead ' || target_title end,
        case when reachable_via_read_tool then 'permissions.deny Read(' || target_title || case when target_is_dir then '/**' else '' end || ')' end
      ) as "Fix"
    from worst
    where rank <= 12
    order by rank;
  EOQ
}

query "agentreach_input_paths" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql},
    ${local.leg_exits_sql},
    ${local.leg_paths_sql}
    select
      '#' || rank || '  ' || source_title || '  →  ' || target_title || '  →  ' || split_part(exit_title, ' (', 1) as label,
      path_id as value
    from worst
    where rank <= 40
    order by rank;
  EOQ
}

query "agentreach_table_path_story" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql},
    ${local.leg_exits_sql},
    ${local.leg_paths_sql},
    pick as (
      select * from worst
      where path_id = coalesce(nullif($3, ''), (select path_id from worst order by rank limit 1))
    )
    select step as "Step", what as "What happens", control as "Control that would stop it", state as "State"
    from (
      select 1 as step,
        source_title || ' ' || case kind_group when 'plugin_hook' then 'runs' when 'mcp' then 'replies' when 'web_tool' then 'are fetched' else 'is read' end
          || ' and contains an instruction you did not write (' || source_detail || ').' as what,
        case kind_group when 'plugin_hook' then 'Review hooks.json before enabling the plugin' when 'mcp' then 'Approve or reject the server when the project opens'
          when 'plugin_file' then 'Review the plugin''s skills and commands, or disable it' when 'web_tool' then 'permissions.deny WebFetch'
          else 'Review the file; strip hidden text' end as control,
        'not done' as state
      from pick
      union all
      select 2, 'Claude Code follows it and runs a ' || via || '.',
        case when via like 'shell command%'
          then 'None by mode: a read-only shell command such as cat runs with no prompt in every mode. permissions.blockReadsOutsideWorkingDirectories makes such reads outside the project prompt'
          else 'permissions.blockReadsOutsideWorkingDirectories. Auto mode prompts only before the first Read outside the project, and "keep allowing" ends that for good' end,
        'mode ' || effective_permission_mode
      from pick
      union all
      select 3, 'The ' || via || ' reads ' || target_title || ', ' || description,
        case when via like 'shell command%' then 'sandbox.filesystem.denyRead covering ' || target_title else 'permissions.deny Read(' || target_title || case when target_is_dir then '/**' else '' end || ')' end,
        case
          when via like 'shell command%' and not sandbox_enabled then 'sandbox off'
          when via like 'shell command%' and not sandbox_enforced then 'sandbox bypassable'
          when via like 'shell command%' then 'no denyRead rule covers it'
          else 'no Read deny rule covers it' end
      from pick
      union all
      select 4, case when exit_kind = 'plugin_hooks'
          then 'The contents reach ' || exit_title || ': hooks receive tool output and the session transcript and run with your network access. Whether a hook sends them anywhere depends on its code, which agentreach does not read.'
          else 'It sends the contents to ' || exit_title || '.' end,
        case exit_kind
          when 'internet' then 'sandbox.network.strictAllowlist with an enforced sandbox'
          when 'allowed_domains' then 'a narrower sandbox.network.allowedDomains'
          when 'web_tool' then 'permissions.deny WebFetch'
          when 'plugin_hooks' then 'disableAllHooks or enabledPlugins'
          when 'mcp_remote' then 'review or remove the remote MCP server'
          when 'mcp_process' then 'review or remove the local MCP server'
          else 'sandbox network rules for local sockets' end,
        case approval when 'none' then 'runs with no prompt' when 'classifier' then 'auto mode''s classifier decides' when 'prompt' then 'asks you first' else 'unknown' end
      from pick
    ) s
    order by step;
  EOQ
}

# ------------------------------------------------------------------
# One path, as a graph. Every node takes the selected path_id; empty
# means the worst path.
# ------------------------------------------------------------------

locals {
  pick_sql = <<-EOQ
    pick as (
      select * from worst
      where path_id = coalesce(nullif($3, ''), (select path_id from worst order by rank limit 1))
    )
  EOQ
}

node "agentreach_path_source_tampered" {
  category = category.agentreach_src_tampered
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select source_id as id, source_title as title,
      jsonb_build_object('why untrusted', source_detail, 'kind', 'instruction file last changed by someone else or carrying hidden text') as properties
    from pick where kind_group = 'instruction_file';
  EOQ
}

node "agentreach_path_source_plugin" {
  category = category.agentreach_src_plugin
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select source_id as id, source_title as title,
      jsonb_build_object('why untrusted', source_detail, 'kind', 'plugin skills, commands and subagents; load into every session') as properties
    from pick where kind_group = 'plugin_file';
  EOQ
}

node "agentreach_path_source_mcp" {
  category = category.agentreach_src_mcp
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select source_id as id, 'MCP server ' || source_title as title,
      jsonb_build_object('why untrusted', source_detail, 'kind', 'project MCP server with no approval decision') as properties
    from pick where kind_group = 'mcp';
  EOQ
}

node "agentreach_path_source_hook" {
  category = category.agentreach_src_hook
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select source_id as id, 'plugin hooks: ' || source_title as title,
      jsonb_build_object('why untrusted', source_detail, 'kind', 'plugin hook; runs outside the sandbox') as properties
    from pick where kind_group = 'plugin_hook';
  EOQ
}

node "agentreach_path_agent" {
  category = category.agentreach_path_agent
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select 'agent' as id, 'Claude Code ' || version || ' runs a ' || via as title,
      jsonb_build_object('permission mode', effective_permission_mode, 'sandbox', case when sandbox_enabled then 'on' else 'off' end) as properties
    from pick;
  EOQ
}

node "agentreach_path_target" {
  category = category.agentreach_path_target
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select 'target' as id, target_title as title,
      jsonb_build_object('holds', description, 'tier', tier, 'sandbox denyRead', coalesce(nullif(sandbox_deny_read_rule, ''), 'none'), 'Read deny', coalesce(nullif(permission_deny_read_rule, ''), 'none')) as properties
    from pick;
  EOQ
}

node "agentreach_path_exit" {
  category = category.agentreach_path_exit
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select 'exit' as id, exit_title as title,
      jsonb_build_object('kind', exit_kind, 'approval', approval) as properties
    from pick;
  EOQ
}

node "agentreach_path_source_web" {
  category = category.agentreach_src_web
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select source_id as id, source_title as title,
      jsonb_build_object('why untrusted', source_detail, 'kind', 'web page fetched during the session') as properties
    from pick where kind_group = 'web_tool';
  EOQ
}

edge "agentreach_path_obeys" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select source_id as from_id, 'agent' as to_id,
      case kind_group when 'plugin_hook' then 'hook runs' when 'mcp' then 'tool output' when 'web_tool' then 'page text' else 'loaded' end
      || ', mode ' || effective_permission_mode as title
    from pick;
  EOQ
}

edge "agentreach_path_reads" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select 'agent' as from_id, 'target' as to_id,
      'read: ' || case when not sandbox_enabled then 'SANDBOX OFF' when not sandbox_enforced then 'SANDBOX BYPASSABLE' when sandbox_deny_read_rule = '' then 'NO DENYREAD' else 'denyRead set' end as title
    from pick;
  EOQ
}

edge "agentreach_path_sends" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  param "path_id" {}
  sql = <<-EOQ
    with ${local.scope_sql}, ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql}, ${local.pick_sql}
    select 'target' as from_id, 'exit' as to_id,
      case when exit_kind = 'plugin_hooks' then 'seen by hooks: ' else 'sent: ' end || case approval when 'none' then 'NO PROMPT' when 'classifier' then 'CLASSIFIER ONLY' when 'prompt' then 'asks you' else 'unknown' end as title
    from pick;
  EOQ
}

query "agentreach_card_sandbox" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}
    select
      'Sandbox' as label,
      case when sandbox_enforced then 'Enforced' when sandbox_enabled then 'On, bypassable' else 'Off' end as value,
      case when sandbox_enforced then 'ok' when sandbox_enabled then 'info' else 'alert' end as type
    from agentreach_agent
    where agent = 'claude_code' and host = (select host from scope)
    limit 1;
  EOQ
}

query "agentreach_card_permission_mode" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}
    select
      'Permission mode' as label,
      effective_permission_mode as value,
      case
        when effective_permission_mode = 'bypassPermissions' then 'alert'
        when effective_permission_mode in ('auto', 'unknown') then 'info'
        else 'ok'
      end as type
    from agentreach_agent
    where agent = 'claude_code' and host = (select host from scope)
    limit 1;
  EOQ
}

# ------------------------------------------------------------------
# Cut one leg
# ------------------------------------------------------------------

query "agentreach_table_cut_one_leg" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}, a as (select * from agentreach_agent where agent = 'claude_code' and host = (select host from scope) limit 1),
    p as (
      select p.* from (select * from agentreach_path where agent = 'claude_code' and host = (select host from scope)) p
      join a on a.host = p.host and a.snapshot_id = p.snapshot_id and a.agent = p.agent
      where p.kind = 'confidentiality' and p.status in ('candidate', 'attested') -- attested: declared closed, not verified
        and p.target_category = any((select categories from scope)::text[])
    ),
    n as (select count(*) as total from p),
    l as (
      select l.* from (select * from agentreach_leg where agent = 'claude_code' and host = (select host from scope)) l
      join a on a.host = l.host and a.snapshot_id = l.snapshot_id and a.agent = l.agent
    ),
    per_category as (
      select
        f.category, f.tier, count(distinct f.path) as files,
        string_agg(distinct '"' || regexp_replace(f.path, '^/Users/[^/]+|^/home/[^/]+', '~') || '"', ', ') as deny_list,
        string_agg(distinct '"Read(//' || ltrim(f.path, '/') || case when f.is_dir then '/**' else '' end || ')"', ', ') as read_deny_list,
        (select count(*) from p where p.target_category = f.category) as closed
      from (select * from agentreach_reach_file where agent = 'claude_code' and host = (select host from scope)) f
      join a on a.host = f.host and a.snapshot_id = f.snapshot_id and a.agent = f.agent
      where f.exists and (f.reachable_via_bash or f.reachable_via_read_tool)
        and f.category = any((select categories from scope)::text[])
      group by f.category, f.tier
    ),
    plugin_names as (
      -- One source per plugin; its title is name@marketplace.
      select string_agg(distinct '"' || l.title || '": false', ', ') as list
      from l
      where l.role = 'untrusted' and l.kind = 'plugin_file' and l.title <> ''
    ),
    fixes as (
      select
        'Enforce the sandbox and refuse unlisted hosts' as fix,
        'sandbox.enabled, allowUnsandboxedCommands, failIfUnavailable, network.strictAllowlist' as setting,
        '{"sandbox": {"enabled": true, "allowUnsandboxedCommands": false, "failIfUnavailable": true, "network": {"strictAllowlist": true}}}' as snippet,
        (select count(*) from p where p.exit_kind in ('internet', 'local_service')) as closed,
        'Closes shell exits to any host and to local services. Allowed domains, WebFetch, MCP servers and plugin hooks stay open.' as note
      from a where not (a.sandbox_enforced and a.network_strict_allowlist)
      union all
      select
        'Deny read of tier-' || c.tier || ' ' || c.category || ' files (' || c.files || ')',
        'sandbox.filesystem.denyRead + permissions.deny',
        '{"sandbox": {"filesystem": {"denyRead": [' || c.deny_list || ']}}, "permissions": {"deny": [' || c.read_deny_list || ']}}',
        c.closed,
        case when a.sandbox_enforced then 'Both layers enforced now.' else 'The Read deny works immediately; denyRead needs an enforced sandbox.' end
      from per_category c, a
      union all
      select
        'Deny WebFetch',
        'permissions.deny',
        '{"permissions": {"deny": ["WebFetch"]}}',
        (select count(*) from p where p.exit_kind = 'web_tool' or p.source_kind = 'web_tool'),
        'Removes fetched pages as a source and WebFetch as an exit. Add WebFetch(domain:...) allow rules for the documentation you need.'
      from a where a.web_fetch_approval <> 'denied'
      union all
      select
        'Approve or reject ' || count(*) || ' MCP server(s) that load without a decision',
        'enabledMcpjsonServers or disabledMcpjsonServers; enabledPlugins for plugin servers',
        concat_ws(', ',
          '{"disabledMcpjsonServers": [' || string_agg(distinct '"' || title || '"', ', ') filter (where position(':' in title) = 0) || ']}',
          '{"enabledPlugins": {' || string_agg(distinct '"' || split_part(title, ':', 1) || '": false', ', ') filter (where position(':' in title) > 0) || '}}'),
        (select count(*) from p where p.source_kind = 'mcp'),
        'Or answer the approval prompt the next time the project opens.'
      from l where l.role = 'untrusted' and l.kind = 'mcp'
      having count(*) > 0
      union all
      select
        'Disable or review plugin hooks (' || count(distinct title) || ' plugin(s))',
        'enabledPlugins',
        '{"enabledPlugins": {' || string_agg(distinct '"' || title || '": false', ', ') || '}}',
        (select count(*) from p where p.source_kind = 'plugin_hook' or p.exit_kind = 'plugin_hooks'),
        'Removes an untrusted input and the hooks exit. Read each hooks.json before re-enabling.'
      from l where l.role = 'untrusted' and l.kind = 'plugin_hook'
      having count(*) > 0
      union all
      select
        'Disable plugins whose skills, commands and subagents you have not read (' || count(distinct title) || ' plugin(s))',
        'enabledPlugins',
        '{"enabledPlugins": {' || coalesce((select list from plugin_names), '') || '}}',
        (select count(*) from p where p.source_kind = 'plugin_file'),
        'Plugin content loads into every session. Re-enable after reading it.'
      from l where l.role = 'untrusted' and l.kind = 'plugin_file'
      having count(*) > 0
      union all
      select
        'Review ' || count(*) || ' instruction file(s) others wrote or can rewrite',
        'review ledger; chmod owner-only',
        '',
        (select count(*) from p where p.source_kind = 'instruction_file'),
        'No setting closes this; it is a review task.'
      from l where l.role = 'untrusted' and l.kind = 'instruction_file'
      having count(*) > 0
    )
    select
      f.fix as "Fix",
      f.setting as "Setting",
      f.closed as "Paths closed",
      case when n.total > 0 then round(100.0 * f.closed / n.total, 1) else 0 end as "Share %",
      f.note as "Note",
      f.snippet as "Snippet"
    from fixes f, n
    where f.closed > 0
    order by f.closed desc, f.fix;
  EOQ
}

# ------------------------------------------------------------------
# Detail tables
# ------------------------------------------------------------------

query "agentreach_table_private_files" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}
    select
      f.tier as "Tier",
      f.category as "Category",
      regexp_replace(f.path, '^/Users/[^/]+|^/home/[^/]+', '~') as "Path",
      f.description as "Holds",
      case
        when f.reachable_via_bash and f.reachable_via_read_tool then 'shell + Read tool'
        when f.reachable_via_bash then 'shell'
        else 'Read tool'
      end as "Via",
      coalesce(nullif(f.sandbox_deny_read_rule, ''), 'none') ||
        case when nullif(f.sandbox_deny_read_rule, '') is not null and not a.sandbox_enabled then ' (not enforced: sandbox off)'
             when nullif(f.sandbox_deny_read_rule, '') is not null and not a.sandbox_enforced then ' (bypassable: ' || a.sandbox_bypasses || ')'
             else '' end as "Deny rule",
      concat_ws(' + ',
        case when f.reachable_via_bash then 'sandbox denyRead' end,
        case when f.reachable_via_read_tool then 'Read deny' end) ||
        case when not a.sandbox_enforced then ' (enforce the sandbox)' else '' end as "Fix"
    from (select * from agentreach_reach_file where agent = 'claude_code' and host = (select host from scope)) f
    join (select * from agentreach_agent where agent = 'claude_code' and host = (select host from scope)) a on a.host = f.host and a.snapshot_id = f.snapshot_id and a.agent = f.agent
    where f.exists and (f.reachable_via_bash or f.reachable_via_read_tool)
      and f.category = any((select categories from scope)::text[])
    order by f.tier, f.category, f.path;
  EOQ
}

query "agentreach_table_mcp_findings" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}
    select
      name as "Server",
      scope as "Scope",
      launcher_type as "Launcher",
      concat_ws('; ',
        case when bool_or(has_inline_secret) then 'inline credential' end,
        case when bool_or(pinned = false and enabled is distinct from false) then 'unpinned ' || launcher_type end, -- a disabled server never launches
        case when scope = 'project' and bool_or(enabled is null) then 'no approval decision' end,
        case when bool_or(coalesce(url, '') <> ''
              and url !~* '^https://'
              and url !~* '^http://(127\.0\.0\.1|localhost|\[::1\])([:/]|$)')
             then 'cleartext url' end
      ) as "Findings",
      count(*) as "Declared in",
      regexp_replace(min(source_path), '^/Users/[^/]+|^/home/[^/]+', '~') as "First declaration"
    from (select * from agentreach_mcp_server where agent = 'claude_code' and host = (select host from scope)) agentreach_mcp_server
    where has_inline_secret
       or (pinned = false and enabled is distinct from false)
       or (scope = 'project' and enabled is null)
       or (coalesce(url, '') <> ''
           and url !~* '^https://'
           and url !~* '^http://(127\.0\.0\.1|localhost|\[::1\])([:/]|$)')
    group by name, scope, launcher_type
    order by bool_or(has_inline_secret) desc, name;
  EOQ
}

query "agentreach_table_hooks" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}
    select
      coalesce(nullif(h.plugin_name, ''), h.scope || ' settings') as "Source",
      h.scope as "Scope",
      case
        when h.scope = 'plugin' and h.plugin_enabled is distinct from false then 'enabled'
        when h.scope = 'plugin' then 'disabled'
        else 'active'
      end as "State",
      count(*) as "Hooks",
      string_agg(distinct h.event, ', ' order by h.event) as "Events",
      case when bool_or(h.third_party) then 'third party' else 'yours' end as "Author",
      case when count(distinct h.source_path) = 1
        then regexp_replace(min(h.source_path), '^/Users/[^/]+|^/home/[^/]+', '~')
        else count(distinct h.source_path) || ' files, first ' || regexp_replace(min(h.source_path), '^/Users/[^/]+|^/home/[^/]+', '~')
      end as "Defined in"
    from (select * from agentreach_hook where agent = 'claude_code' and host = (select host from scope)) h
    group by coalesce(nullif(h.plugin_name, ''), h.scope || ' settings'), h.scope, h.plugin_enabled
    order by bool_or(h.third_party) desc, count(*) desc;
  EOQ
}

# Every agent and harness found on the machine, judged by none of the
# controls: this is the discovery inventory the CLI also prints.
query "agentreach_table_agents" {
  param "host" {
    default = ""
  }
  param "sensitive_categories" {
    default = var.sensitive_categories
  }
  sql = <<-EOQ
    with ${local.scope_sql}
    select
      agent as "Agent",
      coalesce(nullif(version, ''), 'unknown') as "Version",
      coalesce(nullif(effective_permission_mode, ''), 'unknown') as "Permission mode",
      coalesce(nullif(shell_approval, ''), 'unknown') as "Shell gate",
      case
        when sandbox_enforced then 'enforced'
        when sandbox_enabled then 'on, not enforced'
        else 'off'
      end as "Sandbox",
      coalesce(nullif(model_basis, ''), 'docs, no release pin') as "Model basis"
    from (select * from agentreach_agent where host = (select host from scope)) agentreach_agent
    order by agent;
  EOQ
}
