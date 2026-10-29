locals {
  common_tags = {
    project = "agentreach_compliance"
    plugin  = "agentreach"
  }
}

# ------------------------------------------------------------------
# The whole benchmark, grouped the way the posture story reads.
# ------------------------------------------------------------------

benchmark "agentreach" {
  title       = "Coding Agent Security Posture Benchmark v0.1"
  description = "The full posture scan for an AI coding agent: lethal trifecta, agent configuration, hooks, MCP servers, instruction files, reachability, hardening settings, plugins, marketplaces and skills, and CI workflows that run the agent. 12 reviewed core controls and 100 controls still marked needs_validation, whose verdicts are unreviewed: treat them as leads to check, not findings. For the reviewed profile alone, run: powerpipe benchmark run core"
  children = [
    benchmark.lethal_trifecta,
    benchmark.agent_configuration,
    benchmark.hooks,
    benchmark.mcp_servers,
    benchmark.instruction_files,
    benchmark.reachability,
    benchmark.hardening,
    benchmark.supply_chain,
    benchmark.ci_workflows,
  ]
  tags = local.common_tags
}

# ------------------------------------------------------------------
# The AgentReach assessment profile: only the core controls that have a record
# in spec/controls.yaml (what passes, fails or comes back not assessed,
# and the AISVS requirement each supplies evidence for). ci/checks.sh
# fails when this list and the spec disagree.
#   powerpipe benchmark run core
# ------------------------------------------------------------------

benchmark "core" {
  title       = "AgentReach Assessment Profile (core controls)"
  description = "The 12 reviewed core controls from spec/controls.yaml, without the 100 controls still marked needs_validation. 7 map to an OWASP AISVS 1.01 requirement they supply evidence for; 5 are AgentReach requirements with no honest AISVS counterpart. Run with: powerpipe benchmark run core"
  children = [
    control.sandbox_enabled,
    control.permission_mode_allowed,
    control.assessment_complete,
    control.launch_flags_reviewed,
    control.private_data_reachable,
    control.untrusted_instruction_sources,
    control.untrusted_mcp_servers,
    control.exit_channel_open,
    control.attack_path_count,
    control.integrity_paths,
    control.no_inline_secrets,
    control.plugin_hooks_outside_sandbox,
  ]
  tags = local.common_tags
}

# ------------------------------------------------------------------
# The same controls, regrouped by external framework. Each control's
# tags carry its mapping; these benchmarks make the mapping runnable:
#   powerpipe benchmark run cis_controls_v8
# See docs/frameworks.md for the sources and mapping confidence.
# ------------------------------------------------------------------
