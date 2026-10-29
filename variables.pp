# ------------------------------------------------------------------
# Database
# ------------------------------------------------------------------

variable "database" {
  type        = connection.steampipe
  default     = connection.steampipe.default
  description = "The Steampipe database this mod queries. Defaults to the local Steampipe service."
}

# ------------------------------------------------------------------
# Lethal trifecta / reachability
# ------------------------------------------------------------------

variable "sensitive_categories" {
  type        = list(string)
  default     = ["ssh", "cloud_credential", "secrets_manager", "kube", "vcs_credential", "agent_credential", "package_registry", "env_file", "shell_history", "browser"]
  description = "agentreach_reach_file categories that count as private data, everywhere in this mod. Tier 1 (ssh, cloud_credential, secrets_manager, kube) grants access elsewhere; tier 2 (vcs_credential, agent_credential, package_registry) is tokens and agent state; tier 3 (env_file, shell_history, browser) leaks often. Narrow the list to raise the bar."
}

# ------------------------------------------------------------------
# Agent configuration
# ------------------------------------------------------------------

variable "allowed_permission_modes" {
  type        = list(string)
  default     = ["default", "plan", "acceptEdits", "auto"]
  description = "Permission modes a session may start in. dontAsk and bypassPermissions are excluded by default because they remove the human from the loop."
}

variable "require_sandbox" {
  type        = bool
  default     = true
  description = "Whether sandbox.enabled must be true. When false the sandbox control reports info instead of alarm, but every reachability control still tells you what the missing sandbox leaves open."
}

# ------------------------------------------------------------------
# Hooks
# ------------------------------------------------------------------

variable "max_hook_timeout_seconds" {
  type        = number
  default     = 60
  description = "Longest timeout a hook may declare. The agent default is 60 seconds; a longer window is a longer-lived attacker-controlled process if the hook source is ever tampered with."
}

# ------------------------------------------------------------------
# MCP servers
# ------------------------------------------------------------------

variable "allowed_mcp_launchers" {
  type        = list(string)
  default     = ["binary", "node", "python", "remote", "docker", "npx", "uvx", "shell"]
  description = "Launcher types an MCP server may use. Remove npx and uvx to forbid run-latest-from-registry launchers entirely."
}

variable "require_pinned_launchers" {
  type        = bool
  default     = true
  description = "Whether npx and uvx launchers must name an exact package version. When false the pinning control is skipped."
}

# ------------------------------------------------------------------
# Deployment tier
# ------------------------------------------------------------------

variable "deployment" {
  type        = string
  default     = "local"
  description = "How this Claude Code install is governed: local (an individual developer, no administrator), teams (Claude for Teams: an admin can push server-managed settings from the claude.ai console, cached at ~/.claude/remote-settings.json), or enterprise (Claude for Enterprise: managed-settings.json or MDM policy plus server-managed settings). Managed-only keys skip under local, alarm when absent under teams and enterprise, and always alarm when found in a scope where Claude Code ignores them. Under enterprise a protection set only in user settings reports info, because a project file can still override it."
}

variable "max_cleanup_period_days" {
  type        = number
  default     = 30
  description = "Longest local transcript retention (cleanupPeriodDays) allowed. Claude Code defaults to 30; HIPAA guidance keeps it at 30 or lower."
}
