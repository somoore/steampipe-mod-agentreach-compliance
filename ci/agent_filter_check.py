#!/usr/bin/env python3
"""Every SQL block that reads an agent-scoped agentreach_* table must filter
agent = 'claude_code' (or read agentreach_environment, whose rows are
agent = '*' by design).

Codex rows exist in every agent-scoped table. A control or dashboard query
that forgets the filter judges Codex rows by Claude Code rules and mixes two
agents' posture into one row set. The mod's own controls follow the rule;
this check keeps a future control, or a user's copy of one, from silently
breaking it.

Scoped by block, not by file: a named control/query/chart whose SQL uses a
heredoc is checked; the exemption list below is for blocks that legitimately
read both agents and says why. Called by ci/checks.sh.
"""
import glob
import re
import sys

EXEMPT = {
    # ("file", "block name"): reason it may read agent rows unfiltered
    # The discovery inventory lists every agent found on the machine; the
    # mod judges none of them, and no other panel may mix agents.
    ("dashboards/posture.pp", "agentreach_table_agents"):
        "the discovery inventory: lists every agent, judges none",
}
ENVIRONMENT = "agentreach_environment"
FILTER = "agent = 'claude_code'"

problems = []
for f in sorted(glob.glob("controls/*.pp") + glob.glob("dashboards/*.pp")):
    t = open(f).read()
    # Nearest preceding named block gives the SQL a home to report.
    names = [(m.start(), m.group(2)) for m in re.finditer(
        r'\b(control|query|dashboard|chart|node|category|table) "([^"]+)"', t)]
    for m in re.finditer(r"<<-(\w+)\s*\n(.*?)\n[ \t]*\1\b", t, re.S):
        sql = m.group(2)
        tables = set(re.findall(r"\b(agentreach_[a-z_]+)\b", sql))
        agent_scoped = tables - {ENVIRONMENT}
        if not agent_scoped or FILTER in sql:
            continue
        block = ""
        for pos, n in names:
            if pos < m.start():
                block = n
        if (f, block) in EXEMPT:
            continue
        problems.append("%s: block %r reads %s without the agent filter"
                        % (f, block or "?", ", ".join(sorted(agent_scoped))))

for p in problems:
    print(p)
if not problems:
    print("every SQL block filters agent = 'claude_code'")
sys.exit(1 if problems else 0)
