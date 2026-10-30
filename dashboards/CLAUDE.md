## Dashboard conventions

The page is built for a developer asking "how does this help me", in this order: a generated verdict sentence; six cards; the **worst paths** table (one row per private file, worst source, best exit, blocked-by, fix); a **select input** that defaults to path #1 and drives a four-node **path graph** (source → Claude Code → file → exit) whose edge titles name the missing control in capitals; a plain-words table for the same path; then the cut-one-leg table and detail tables.

Rules:
- The page shows one machine at a time. The `host` input (first in the page, no placeholder) feeds every query as `param "host"`; every query puts `${local.scope_sql}` first in its WITH list, and every table read in a leg local filters on `host = (select host from scope)`. Every query takes `host` as `$1` and `sensitive_categories` as `$2` (scope carries both); `path_id` is `$3`. The leg locals read the categories from `scope`, so `var.sensitive_categories` narrows every panel. Never add a query that reads a `agentreach_*` table without that filter.
- Concrete nouns only. A node is a file path, a server name, a plugin name or a host. Never a category, a count, or a control. Controls live on edge titles and in the "Control that would stop it" column.
- Paths and legs come from the plugin's `agentreach_path` and `agentreach_leg`; `local.leg_paths_sql` (controls/legs.pp) only renames columns. `worst` is one row per private file, picking the path with the weakest `approval` first; `paths` is every candidate confidentiality path. Every path panel takes `param "path_id"` and resolves an empty value to the worst path via `local.pick_sql`.
- The verdict card says "Not fully assessed" when `collect_errors` is non-empty or probes were off (AG-06), before any count.
- The input must not set `placeholder`; without one Powerpipe selects the first row, which is why #1 renders on load. With a placeholder every dependent panel waits forever.
- Icons are Material Symbols names on the category blocks in `dashboards/theme.pp`: description, extension, hub, bolt, public, terminal, key, cloud_upload. Every category has `fold { threshold = 100 }` so Powerpipe never collapses nodes.
- The cut-one-leg table counts the `agentreach_path` rows each fix removes; it never multiplies leg counts, because legs that only load in different projects do not pair. Do not put a path count on the page as a headline number.

## Framework pages

There are none. The per-framework pages were removed on 2026-10-28 and live on the `frameworks-archive` branch. `posture.pp` is the only dashboard; do not add framework pages back.
