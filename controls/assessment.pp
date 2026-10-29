# Shared pieces of the core controls (see spec/controls.yaml for which
# controls are core and what each one proves).
#
# A core control reads agentreach_agent as `a`, keeps agent = 'claude_code' unless
# it is agent-neutral, joins every other table on host, snapshot_id and agent
# so a fleet connection never mixes machines, and emits at least one row per
# agent so a host with nothing to report is still visible.
#
# Not assessed: when the evidence a control needs is missing, it returns
# skip with a reason that starts "Not assessed:". Configuration controls need
# every settings source to have been read; reachability controls also need
# the probes to have run. AG-06 alarms on either and names the cause.

locals {
  not_assessed_config_sql = "(coalesce(jsonb_array_length(a.collect_errors), 0) > 0)"
  not_assessed_probe_sql  = "(coalesce(jsonb_array_length(a.collect_errors), 0) > 0 or not a.probed)"
  not_assessed_reason_sql = "case when coalesce(jsonb_array_length(a.collect_errors), 0) > 0 then 'Not assessed: ' || jsonb_array_length(a.collect_errors) || ' configuration source(s) could not be read, so this verdict could be wrong either way; see AG-06.' else 'Not assessed: probes were off, so reachability is unknown; see AG-06.' end"
  same_snapshot_sql       = "a.host = %[1]s.host and a.snapshot_id = %[1]s.snapshot_id and a.agent = %[1]s.agent"
}
