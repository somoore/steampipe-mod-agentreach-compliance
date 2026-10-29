# Palette for the posture dashboard. Powerpipe cannot inject CSS, so colour
# and icon come from category blocks on the path graph. Every category has a
# title so the graph renders a legend. Icons are Material Symbols names.

locals {
  agentreach_untrusted = "#F59E0B" # amber: content the agent obeys but you did not write
  agentreach_agent     = "#2563EB" # blue: the agent
  agentreach_private   = "#DC2626" # red: the private file it reads
  agentreach_exit      = "#7F1D1D" # dark red: where the data leaves
}

category "agentreach_src_tampered" {
  title = "Instruction file you did not write or that carries hidden text"
  color = local.agentreach_untrusted
  icon  = "description"
  fold {
    threshold = 100
  }
}

category "agentreach_src_plugin" {
  title = "Plugin skill, command or subagent"
  color = local.agentreach_untrusted
  icon  = "extension"
  fold {
    threshold = 100
  }
}

category "agentreach_src_mcp" {
  title = "MCP server with no approval decision"
  color = local.agentreach_untrusted
  icon  = "hub"
  fold {
    threshold = 100
  }
}

category "agentreach_src_hook" {
  title = "Plugin hook (runs outside the sandbox)"
  color = local.agentreach_untrusted
  icon  = "bolt"
  fold {
    threshold = 100
  }
}

category "agentreach_src_web" {
  title = "Web page the agent fetched"
  color = local.agentreach_untrusted
  icon  = "public"
  fold {
    threshold = 100
  }
}

category "agentreach_path_agent" {
  title = "Claude Code"
  color = local.agentreach_agent
  icon  = "terminal"
  fold {
    threshold = 100
  }
}

category "agentreach_path_target" {
  title = "Private file it reads"
  color = local.agentreach_private
  icon  = "key"
  fold {
    threshold = 100
  }
}

category "agentreach_path_exit" {
  title = "Where the data leaves"
  color = local.agentreach_exit
  icon  = "cloud_upload"
  fold {
    threshold = 100
  }
}
