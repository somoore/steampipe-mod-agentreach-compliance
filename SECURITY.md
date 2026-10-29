# Security policy

## Reporting a vulnerability

Do not open a public issue for a vulnerability.

Use GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on this repository. Include what you found, how to reproduce
it, and whether you plan to publish it. Reports are answered within 7 days.
Coordinated disclosure is preferred; credit is given on request.

## Scope

- Any control that reports `ok` for an unsafe state, or mixes one machine's
  rows into another's (every query filters on the selected host).
- SQL injection through the template machinery in `controls/hardening.pp`.
- The CI checks (`ci/`) and the fixture expectations.
- Out of scope: the plugin's collectors (report those in the
  [plugin repository](https://github.com/somoore/steampipe-plugin-agentreach))
  and the vendors' own products.

## Design guarantees to test against

- Controls never fix anything and never write: they return
  resource/status/reason rows only.
- No secret value is ever selected, displayed or concatenated.
- Null means unknown or unrestricted, never false; "not assessed" is `skip`,
  never `ok`.
