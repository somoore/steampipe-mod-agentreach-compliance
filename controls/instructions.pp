benchmark "instruction_files" {
  title       = "5. Instruction files"
  description = "CLAUDE.md, AGENTS.md, rules, skills, subagents and commands are text the model treats as instructions. These controls look for content that reaches the model but not the reviewer: hidden Unicode, HTML comments, and pulls from outside the file."
  children = [
    control.no_hidden_unicode,
    control.no_html_comments,
    control.external_includes_reviewed,
    control.project_instruction_files_tracked,
    control.third_party_instruction_files,
  ]
  tags = merge(local.common_tags, { group = "instruction_files" })
}

control "no_hidden_unicode" {
  title       = "Instruction files contain no hidden Unicode"
  description = "Zero-width characters, bidirectional overrides and Unicode tag characters render as nothing in a diff viewer and as text to the model. They are the canonical invisible prompt-injection payload. Fix: open the file in an editor that shows invisible characters, remove them, and add a pre-commit check."
  severity    = "critical"
  tags = merge(local.common_tags, {
    agentreach                       = "IF-01"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM01:2025 Prompt Injection"
    owasp_agentic              = "ASI01 Agent Goal Hijack"
    cis_controls_v8            = "16.1"
    aws_coding_agent_framework = "R001"
    owasp_agent_cheatsheet     = "2"
    knostic_threat_model       = "7"
  })

  sql = <<-EOQ
    select
      path as resource,
      case when hidden_unicode_count > 0 then 'alarm' else 'ok' end as status,
      case
        when hidden_unicode_count > 0
          then path || ' contains ' || hidden_unicode_count || ' zero-width, bidi or tag character(s) the model reads and reviewers cannot see. Strip them and reject them in pre-commit.'
        else path || ' has no hidden Unicode.'
      end as reason,
      kind,
      scope
    from (select * from agentreach_instruction_file where agent = 'claude_code') agentreach_instruction_file;
  EOQ
}

control "no_html_comments" {
  title       = "Instruction files contain no HTML comments"
  description = "Markdown renderers hide <!-- comments -->; the model does not. A comment is a place to put instructions that a reviewer reading the rendered file never sees. Fix: delete the comment or turn it into visible text."
  severity    = "medium"
  tags = merge(local.common_tags, {
    agentreach                       = "IF-02"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM01:2025 Prompt Injection"
    owasp_agentic              = "ASI01 Agent Goal Hijack"
    cis_controls_v8            = "16.1"
    aws_coding_agent_framework = "R001"
    owasp_agent_cheatsheet     = "2"
    knostic_threat_model       = "7"
  })

  sql = <<-EOQ
    select
      path as resource,
      case when html_comment_count > 0 then 'alarm' else 'ok' end as status,
      case
        when html_comment_count > 0
          then path || ' has ' || html_comment_count || ' HTML comment(s) that reach the model but not a reader of the rendered file. Make the text visible or remove it.'
        else path || ' has no HTML comments.'
      end as reason,
      kind,
      scope
    from (select * from agentreach_instruction_file where agent = 'claude_code') agentreach_instruction_file;
  EOQ
}

control "external_includes_reviewed" {
  title       = "Instruction files that pull in other files or link out are known"
  description = "An @path include drags another file into context; a URL invites the model to fetch content nobody reviewed with this file. Neither is wrong, but both widen what the agent obeys. Rows with includes or URLs report info so you can review the targets."
  severity    = "low"
  tags = merge(local.common_tags, {
    agentreach                       = "IF-03"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM01:2025 Prompt Injection"
    owasp_agentic              = "ASI06 Memory and Context Poisoning"
    cis_controls_v8            = "16.1"
    aws_coding_agent_framework = "Context as a security control"
    owasp_agent_cheatsheet     = "2"
    knostic_threat_model       = "6"
  })

  sql = <<-EOQ
    select
      path as resource,
      case when external_include_count > 0 or external_url_count > 0 then 'info' else 'ok' end as status,
      case
        when external_include_count > 0 and external_url_count > 0
          then path || ' includes ' || external_include_count || ' file(s) via @path and references ' || external_url_count || ' URL(s). Review each target.'
        when external_include_count > 0
          then path || ' includes ' || external_include_count || ' file(s) via @path. Review each included file as part of this one.'
        when external_url_count > 0
          then path || ' references ' || external_url_count || ' URL(s). Content behind them is not reviewed with this file.'
        else path || ' is self-contained.'
      end as reason,
      kind,
      scope
    from (select * from agentreach_instruction_file where agent = 'claude_code') agentreach_instruction_file;
  EOQ
}

control "project_instruction_files_tracked" {
  title       = "Repository-tracked instruction files are listed"
  description = "Instruction files checked into git are expected and useful; being tracked is not a finding. They are listed (info) because a pull request from someone else can change what the agent does, so the list deserves the same review care as CI configuration. The third_party control is where authorship becomes a finding."
  severity    = "low"
  tags = merge(local.common_tags, {
    agentreach                       = "IF-04"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM01:2025 Prompt Injection"
    owasp_agentic              = "ASI01 Agent Goal Hijack"
    cis_controls_v8            = "16.1"
    aws_coding_agent_framework = "Context as a security control"
    owasp_agent_cheatsheet     = "2"
    knostic_threat_model       = "6"
  })

  sql = <<-EOQ
    select
      path as resource,
      case when tracked_in_git then 'info' else 'ok' end as status,
      case
        when tracked_in_git then path || ' (' || kind || ') is tracked in git. Treat changes to it like changes to CI config: reviewed, from trusted authors.'
        else path || ' (' || kind || ') is local to this machine.'
      end as reason,
      kind,
      project_dir
    from (select * from agentreach_instruction_file where agent = 'claude_code') agentreach_instruction_file
    where scope = 'project';
  EOQ
}

control "third_party_instruction_files" {
  title       = "Third-party instruction files are reviewed and carry no hidden text"
  description = "A file is third party when a plugin ships it or when its last commit came from someone other than the repository's own identity. Such a file is untrusted content by definition and reports info so it is reviewed; if it also carries hidden Unicode or HTML comments it alarms, because hidden text from a third party is the exact shape of a planted instruction. Fix: read plugin skills, commands and subagents before enabling the plugin, pin plugin versions, and strip hidden text."
  severity    = "high"
  tags = merge(local.common_tags, {
    agentreach                       = "IF-05"
    agentreach_class                 = "needs_validation"
    owasp_llm_2025             = "LLM03:2025 Supply Chain"
    owasp_agentic              = "ASI04 Agentic Supply Chain"
    cis_controls_v8            = "16.1"
    aws_coding_agent_framework = "R004"
    owasp_agent_cheatsheet     = "2"
    knostic_threat_model       = "6"
  })

  sql = <<-EOQ
    select
      path as resource,
      case
        when hidden_unicode_count > 0 or html_comment_count > 0 then 'alarm'
        else 'info'
      end as status,
      case
        when hidden_unicode_count > 0 or html_comment_count > 0
          then path || ' (' || kind || ') is third party (' || coalesce(nullif(plugin_name, ''), 'last commit by ' || coalesce(nullif(git_last_author, ''), 'someone else')) || ') and carries '
            || concat_ws(' and ', nullif(hidden_unicode_count, 0) || ' hidden Unicode char(s)', nullif(html_comment_count, 0) || ' HTML comment(s)')
            || '. Hidden text from a third party is a planted instruction until proven otherwise; strip it or remove the file.'
        when coalesce(plugin_name, '') <> ''
          then path || ' (' || kind || ') ships with plugin ' || plugin_name || '. Read it before trusting the plugin; it loads into every session where the plugin is enabled.'
        else path || ' (' || kind || ') was last committed by ' || coalesce(nullif(git_last_author, ''), 'someone else') || '. Review it as you would a change to CI config.'
      end as reason,
      kind,
      scope,
      plugin_name
    from (select * from agentreach_instruction_file where agent = 'claude_code') agentreach_instruction_file
    where third_party
    order by (hidden_unicode_count > 0 or html_comment_count > 0) desc, scope, path;
  EOQ
}
