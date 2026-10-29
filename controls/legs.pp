# The legs of the lethal trifecta and the integrity pairing are computed once,
# by the plugin (pkg/posture/paths.go), and exposed as agentreach_leg (every leg)
# and agentreach_path (the legs that meet in one session). The fragments below only
# rename columns for the dashboard. They never decide what counts as a leg;
# if a leg looks wrong, fix paths.go.
#
#   untrusted : content the agent obeys that the user did not write or review
#   private   : sensitive files the agent can open (shell or Read tool)
#   exits     : channels data can leave through, with the approval each needs
#
# Each fragment is a CTE body (no leading "with"), so callers write:
#   with ${local.leg_untrusted_sql}, ${local.leg_exits_sql} select ...

locals {
  # Home-directory paths read better as ~ on a dashboard.
  tilde_sql = "regexp_replace(%s, '^/Users/[^/]+|^/home/[^/]+', '~')"

  leg_untrusted_sql = <<-EOQ
    untrusted as (
      select l.host, l.snapshot_id, l.agent, l.kind as kind_group, l.leg_id as id, l.title, l.detail, l.project_dir, l.evidence
      from (select * from agentreach_leg where agent = 'claude_code' and host = (select host from scope)) l
      where l.role = 'untrusted'
    )
  EOQ

  leg_exits_sql = <<-EOQ
    exits as (
      select l.host, l.snapshot_id, l.agent, l.leg_id as id, l.title, l.kind, l.detail, l.project_dir, l.evidence, l.approval, l.rank
      from (select * from agentreach_leg where agent = 'claude_code' and host = (select host from scope)) l
      where l.role = 'exit'
    )
  EOQ
}

# Every leg local reads only the host the dashboard shows, and counts only
# the private-data categories in var.sensitive_categories: callers put
# ${local.scope_sql} first in their WITH list, with the host as $1 and the
# categories (JSON) as $2.
locals {
  scope_sql = <<-EOQ
    scope as (
      select coalesce(nullif($1, ''), (select min(host) from agentreach_agent where agent = 'claude_code')) as host,
        array(select jsonb_array_elements_text($2::jsonb)) as categories
    )
  EOQ
}

# Confidentiality paths, one row per (untrusted source, private file, exit),
# with the rank fields the dashboard sorts by. Callers write:
#   with ${local.leg_untrusted_sql}, ${local.leg_exits_sql}, ${local.leg_paths_sql} select ...
locals {
  leg_paths_sql = <<-EOQ
    targets as (
      select distinct on (f.host, f.snapshot_id, f.agent, f.path)
        f.host, f.snapshot_id, f.agent, f.path, f.category, f.tier, f.description, f.is_dir,
        regexp_replace(f.path, '^/Users/[^/]+|^/home/[^/]+', '~') as title,
        f.reachable_via_bash, f.reachable_via_read_tool,
        f.sandbox_deny_read_rule, f.permission_deny_read_rule,
        case f.category
          when 'ssh' then 'SSH keys' when 'cloud_credential' then 'cloud credentials'
          when 'secrets_manager' then 'secret stores' when 'kube' then 'kubeconfigs'
          when 'vcs_credential' then 'VCS tokens' when 'agent_credential' then 'other agents'' tokens'
          when 'package_registry' then 'registry tokens' when 'env_file' then '.env files'
          when 'shell_history' then 'shell history' when 'browser' then 'browser profiles'
          else f.category end as category_label
      from (select * from agentreach_reach_file where agent = 'claude_code' and host = (select host from scope)) f
      where f.exists
        and f.category = any((select categories from scope)::text[])
      order by f.host, f.snapshot_id, f.agent, f.path, f.project_dir
    ),
    paths as (
      select
        p.path_id,
        p.source_id, p.source_kind as kind_group, p.source_title, p.source_detail,
        t.path, t.title as target_title, t.is_dir as target_is_dir, t.category, t.category_label, t.tier, t.description,
        t.reachable_via_bash, t.reachable_via_read_tool, t.sandbox_deny_read_rule, t.permission_deny_read_rule,
        case p.via when 'shell' then 'shell command' when 'shell_retry' then 'shell command (retried outside the sandbox)' else 'Read tool' end as via,
        p.exit_id, p.exit_title, p.exit_kind, p.approval, p.project_dir,
        a.sandbox_enabled, a.sandbox_enforced, a.effective_permission_mode, a.version,
        p.source_rank, p.exit_rank,
        case p.approval when 'none' then 0 when 'classifier' then 1 when 'unknown' then 2 else 3 end as approval_rank
      from (select * from agentreach_path where agent = 'claude_code' and host = (select host from scope)) p
      join targets t on t.host = p.host and t.snapshot_id = p.snapshot_id and t.agent = p.agent and t.path = p.target_path
      join (select * from agentreach_agent where agent = 'claude_code' and host = (select host from scope)) a on a.host = p.host and a.snapshot_id = p.snapshot_id and a.agent = p.agent
      where p.kind = 'confidentiality' and p.status in ('candidate', 'attested') -- attested: declared closed, not verified
    ),
    worst as (
      -- one row per private file: the path with the weakest gate, then the
      -- worst source and best exit, so the list reads as "what could happen
      -- to each of your secrets"; ranked worst first. other_sources counts
      -- the sources not shown.
      select *,
        row_number() over (order by tier, approval_rank, source_rank, exit_rank, path) as rank
      from (
        select distinct on (path) p.*,
          (select count(distinct source_id) from paths q where q.path = p.path) - 1 as other_sources
        from paths p
        order by path, approval_rank, source_rank, exit_rank, source_title, exit_title, path_id -- total order: every panel picks the same row
      ) p
    )
  EOQ
}
