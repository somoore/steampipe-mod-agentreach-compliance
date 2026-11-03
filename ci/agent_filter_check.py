#!/usr/bin/env python3
"""Every SQL block that reads an agent-scoped agentreach_* table must filter
agent = 'claude_code' (or read agentreach_environment, whose rows are
agent = '*' by design), and every join that pairs rows by agent must also
match host and snapshot_id.

Codex rows exist in every agent-scoped table. A control or dashboard query
that forgets the filter judges Codex rows by Claude Code rules and mixes two
agents' posture into one row set. A join on agent alone does the same across
machines: with a fleet connection it grades one machine's files with another
machine's settings and reports every row once per host. The mod's own
controls follow both rules; this check keeps a future control, or a user's
copy of one, from silently breaking them.

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


def join_clauses(sql):
    """Yield (offset, text) for each JOIN clause, stopping at the next
    top-level keyword so nested subqueries are not truncated."""
    for m in re.finditer(r"\bjoin\b", sql, re.I):
        depth, i, end = 0, m.end(), len(sql)
        while i < len(sql):
            ch = sql[i]
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    end = i
                    break
                depth -= 1
            elif depth == 0 and re.match(
                    r"\b(join|where|group\s+by|order\s+by|limit|union|window)\b",
                    sql[i:], re.I):
                end = i
                break
            i += 1
        yield m.start(), sql[m.start():end]


def strip_sql_comments(sql):
    """Drop SQL comments so a filter that survives only in a comment does not
    satisfy the check (a comment is not a WHERE clause)."""
    sql = re.sub(r"/\*.*?\*/", " ", sql, flags=re.S)
    return re.sub(r"--[^\n]*", " ", sql)


problems = []
for f in sorted(glob.glob("controls/*.pp") + glob.glob("dashboards/*.pp")):
    t = open(f).read()
    # Nearest preceding named block gives the SQL a home to report.
    names = [(m.start(), m.group(2)) for m in re.finditer(
        r'\b(control|query|dashboard|chart|node|category|table) "([^"]+)"', t)]
    for m in re.finditer(r"<<-(\w+)\s*\n(.*?)\n[ \t]*\1\b", t, re.S):
        sql = m.group(2)
        code = strip_sql_comments(sql)
        tables = set(re.findall(r"\b(agentreach_[a-z_]+)\b", sql))
        agent_scoped = tables - {ENVIRONMENT}
        if not agent_scoped or FILTER in code:
            continue
        block = ""
        for pos, n in names:
            if pos < m.start():
                block = n
        if (f, block) in EXEMPT:
            continue
        problems.append("%s: block %r reads %s without the agent filter"
                        % (f, block or "?", ", ".join(sorted(agent_scoped))))

for f in sorted(glob.glob("controls/*.pp") + glob.glob("dashboards/*.pp")):
    t = open(f).read()
    names = [(m.start(), m.group(2)) for m in re.finditer(
        r'\b(control|query|dashboard|chart|node|category|table) "([^"]+)"', t)]
    for m in re.finditer(r"<<-(\w+)\s*\n(.*?)\n[ \t]*\1\b", t, re.S):
        sql = m.group(2)
        # Recompute per block: `code` must hold this block's SQL, not a
        # stale heredoc left over from the filter pass above.
        code = strip_sql_comments(sql)
        block = ""
        for pos, n in names:
            if pos < m.start():
                block = n
        for _, clause in join_clauses(code):
            # agent = ... alone is not a machine identity: in a fleet
            # connection it pairs every copy of a row with every snapshot's
            # settings, so one machine's hardening grades another's files.
            if not re.search(r"\.agent\s*=\s*\w+\.agent", clause):
                continue
            if re.search(r"\.host\s*=", clause) and re.search(r"\.snapshot_id\s*=", clause):
                continue
            problems.append(
                "%s: block %r joins on agent without host and snapshot_id "
                "(a fleet connection would mix machines)" % (f, block or "?"))

for p in problems:
    print(p)
if not problems:
    print("every SQL block filters agent = 'claude_code' and joins on the same snapshot")
sys.exit(1 if problems else 0)
