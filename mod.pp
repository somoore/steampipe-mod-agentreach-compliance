mod "agentreach_compliance" {
  database    = var.database
  title       = "Coding Agent Security Posture Benchmark"
  description = "Deterministic posture checks for AI coding agents (Claude Code first): what the agent can read, what it obeys, and where it can send data. One benchmark (agentreach) holds every control; a reviewed core profile of 12 controls is built on OWASP AISVS 1.01 and the rest are marked needs_validation until they earn a spec record. Runs against the steampipe-plugin-agentreach tables."
  color       = "#DC2626"
  categories  = ["security", "compliance", "ai"]

  opengraph {
    title       = "Coding Agent Security Posture Benchmark for Powerpipe"
    description = "Inert posture controls, a reviewed core profile built on OWASP AISVS, and an attack-path dashboard for AI coding agents: the lethal trifecta (private data, untrusted content, exit channel), hooks, MCP servers, instruction files and reachability."
  }

  require {
    plugin "agentreach" {
      min_version = "0.2.0"
    }
  }
}
