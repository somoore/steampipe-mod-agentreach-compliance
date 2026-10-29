# ------------------------------------------------------------------
# 9. CI workflows: GitHub Actions steps that run a coding agent. A
# workflow starts a session with no person at the prompt, and its trigger
# decides whose text reaches the agent. agentreach reads the workflow files of
# known projects (agentreach_ci_workflow); it does not see runs.
# Docs: code.claude.com/docs/en/github-actions and the claude-code-action
# security guide (docs/security.md in anthropics/claude-code-action).
# ------------------------------------------------------------------

locals {
  # How a step is named in a reason, and its triggers as a list.
  ci_step_sql     = "case w.launcher when 'claude_code_action' then 'The Claude Code action' when 'claude_code_base_action' then 'The Claude Code base action' else 'A run step that calls claude -p' end"
  ci_source_sql   = "case w.permission_mode_source when 'flag' then 'a command-line flag' when 'settings_input' then 'the settings input' when 'project_settings' then '.claude/settings.json' else 'the built-in default' end"
  ci_triggers_sql = "coalesce((select string_agg(t, ', ') from jsonb_array_elements_text(w.triggers) t), 'no listed event')"
}

benchmark "ci_workflows" {
  title       = "9. CI workflows"
  description = "GitHub Actions steps that run Claude Code: who can start them, whether they run a pull request's tree with the base repository's secrets, whether any shell command runs on untrusted input, and whether the action is pinned. Read from .github/workflows in the repositories of known projects."
  children = [
    control.ci_pr_head_not_checked_out,
    control.ci_actor_check_kept,
    control.ci_shell_restricted,
    control.ci_actions_pinned,
  ]
  tags = local.common_tags
}

control "ci_pr_head_not_checked_out" {
  title       = "CI agents do not run in a pull request's tree with the base repository's secrets"
  description = "pull_request_target and workflow_run run with the base repository's secrets. A step that checks out the pull request head at the workspace root before the agent hands it a tree the pull request author wrote: for a run step or the base action that includes .claude/settings.json hooks and CLAUDE.md, and for the Claude Code action, which restores those from the base branch, package scripts, the Makefile and linter config that hooks may run. Fix: check out the base ref at the root and the head into a subdirectory passed with --add-dir (claude-code-action security guide)."
  severity    = "critical"
  tags        = merge(local.common_tags, { agentreach = "CI-01", agentreach_class = "needs_validation" })

  sql = <<-EOQ
    select
      w.path || ':' || w.line as resource,
      case when w.base_secrets_trigger and w.checks_out_head then 'alarm' else 'ok' end as status,
      case
        when w.base_secrets_trigger and w.checks_out_head
          then ${local.ci_step_sql} || ' runs on ' || ${local.ci_triggers_sql}
            || ' after a step checks out the pull request head at the workspace root, so the agent works in a tree the pull request author wrote, with the base repository''s secrets'
            || case when jsonb_array_length(w.secrets) > 0 then ' (' || (select string_agg(s, ', ') from jsonb_array_elements_text(w.secrets) s) || ')' else '' end
            || '. Check out the base ref at the root (actions/checkout with no ref) and the head into a subdirectory passed with --add-dir.'
        when w.checks_out_head
          then ${local.ci_step_sql} || ' runs after a step checks out the pull request head, but none of its triggers (' || ${local.ci_triggers_sql} || ') gives that run the base repository''s secrets.'
        else ${local.ci_step_sql} || ' runs in the checkout its trigger gives it; no earlier step checks out a pull request head at the workspace root.'
      end as reason,
      w.project_dir,
      w.host
    from (select * from agentreach_ci_workflow where agent = 'claude_code') w;
  EOQ
}

control "ci_actor_check_kept" {
  title       = "CI agents that outsiders can trigger keep the write-access check"
  description = "issues, issue_comment, discussion, pull_request_target and workflow_run events can be caused by someone without write access, and those runs have the repository's secrets. The Claude Code action refuses users without write access and rejects bots unless allowed_bots lists them; allowed_non_write_users and allowed_bots: '*' remove those checks, and the base action and run steps that call claude -p never had them (claude-code-action security guide). Fix: use the Claude Code action, drop allowed_non_write_users, list bots by name, or move the job to a trigger only collaborators can cause."
  severity    = "high"
  tags        = merge(local.common_tags, { agentreach = "CI-02", agentreach_class = "needs_validation" })

  sql = <<-EOQ
    select
      w.path || ':' || w.line as resource,
      case
        when w.outsider_trigger and (w.actor_check in ('none', 'relaxed') or w.allowed_bots = 'all') then 'alarm'
        else 'ok'
      end as status,
      case
        when w.outsider_trigger and w.actor_check = 'none'
          then ${local.ci_step_sql} || ' runs on ' || ${local.ci_triggers_sql} || ', which someone without write access can cause, and it checks nobody. Use the Claude Code action, which refuses users without write access, or move the job to a trigger only collaborators can cause.'
        when w.outsider_trigger and w.actor_check = 'relaxed'
          then ${local.ci_step_sql} || ' runs on ' || ${local.ci_triggers_sql} || ', and allowed_non_write_users lets users without write access start it. Remove allowed_non_write_users, or keep that job''s token to the one scope it needs.'
        when w.outsider_trigger and w.allowed_bots = 'all'
          then ${local.ci_step_sql} || ' runs on ' || ${local.ci_triggers_sql} || ', and allowed_bots: ''*'' lets any bot or GitHub App start it, unchecked for repository permissions. List the bots it needs by name.'
        when w.outsider_trigger then ${local.ci_step_sql} || ' refuses users without write access and bots it does not list.'
        else ${local.ci_step_sql} || ' runs on ' || ${local.ci_triggers_sql} || '; none of them lets someone without write access start it with the repository''s secrets.'
      end as reason,
      w.project_dir,
      w.host
    from (select * from agentreach_ci_workflow where agent = 'claude_code') w;
  EOQ
}

control "ci_shell_restricted" {
  title       = "CI agents on untrusted input cannot run any shell command"
  description = "In CI nobody answers a prompt, so a call that needs approval is denied (docs: Agent SDK permissions, default mode), unless bypassPermissions or a blanket Bash allow rule (Bash, Bash(*)) approves every command first. On an issue, comment, review, discussion or pull request event, text someone else wrote reaches the agent; with any command allowed, one injected instruction runs with the job's token and secrets. Status: alarm on an untrusted trigger, info on a trigger only collaborators cause. Fix: remove --dangerously-skip-permissions and permission-mode bypassPermissions, and replace a blanket Bash rule with the commands the job needs."
  severity    = "critical"
  tags        = merge(local.common_tags, { agentreach = "CI-03", agentreach_class = "needs_validation" })

  sql = <<-EOQ
    select
      w.path || ':' || w.line as resource,
      case
        when w.unrestricted_shell and w.untrusted_trigger then 'alarm'
        when w.unrestricted_shell then 'info'
        else 'ok'
      end as status,
      case
        when w.unrestricted_shell
          then ${local.ci_step_sql} || ' lets any shell command run with no approval ('
            || case when w.skip_permissions then 'bypassPermissions from ' || ${local.ci_source_sql} else 'a blanket Bash allow rule' end
            || case when w.untrusted_trigger
                 then '), on ' || ${local.ci_triggers_sql} || ', where text someone else wrote reaches the agent'
                 else '); its triggers (' || ${local.ci_triggers_sql} || ') are ones only collaborators cause'
               end
            || '. The job token has '
            || case
                 when not w.permissions_declared then 'the repository''s default permissions'
                 when jsonb_array_length(w.write_scopes) = 0 then 'no write scopes'
                 else 'write on ' || (select string_agg(s, ', ') from jsonb_array_elements_text(w.write_scopes) s)
               end
            || '. '
            || case when w.skip_permissions
                 then 'Remove --dangerously-skip-permissions or permission-mode bypassPermissions and allow the commands the job needs with --allowedTools.'
                 else 'Replace the blanket Bash rule with the commands the job needs, such as Bash(npm test).'
               end
        else ${local.ci_step_sql} || ' starts in ' || w.permission_mode || ' mode (from ' || ${local.ci_source_sql} || ') with ' || w.allow_rules || ' allow rule(s) and no blanket Bash rule; a call that needs approval is denied, since nobody is there to approve it.'
      end as reason,
      w.project_dir,
      w.host
    from (select * from agentreach_ci_workflow where agent = 'claude_code') w;
  EOQ
}

control "ci_actions_pinned" {
  title       = "Claude Code actions are pinned to a commit"
  description = "A tag such as @v1 moves: whoever controls the action's repository, or an attacker who takes it over, decides what runs next with the workflow's secrets. GitHub's hardening guide recommends a full-length commit SHA as the only immutable reference. Run steps are not listed. Fix: pin uses: anthropics/claude-code-action@<sha> and update it on purpose (Dependabot can keep SHA pins current)."
  severity    = "medium"
  tags        = merge(local.common_tags, { agentreach = "CI-04", agentreach_class = "needs_validation" })

  sql = <<-EOQ
    select
      w.path || ':' || w.line as resource,
      case when w.pinned then 'ok' else 'alarm' end as status,
      case
        when w.pinned then ${local.ci_step_sql} || ' is pinned to a commit.'
        when w.action_ref = '' then ${local.ci_step_sql} || ' names a ref agentreach cannot read; pin it to a full commit SHA.'
        else ${local.ci_step_sql} || ' uses @' || w.action_ref || ', which can move; pin it to a full commit SHA.'
      end as reason,
      w.project_dir,
      w.host
    from (select * from agentreach_ci_workflow where agent = 'claude_code') w
    where w.launcher <> 'run';
  EOQ
}
