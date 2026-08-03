# Migration note

## Behavior changes

1. `GET /api/v1/licenses/{id}` is now a single canonical handler with explicit `Accept` negotiation and `406` for unsupported representations.
2. Static routes (`/taxonomy`, `/cache/status`, `/spdx3/minimal`) are protected from `{id}` shadowing.
3. Identifier resolution is unified (SPDX ID, UUID, encoded URI, aliases) and uses UUID validation instead of string-length heuristics.
4. Optional `/original`, `/legal`, `/machine` semantics are strict:
   - no silent fallback from `/legal` to generic SPDX text;
   - `/machine` requires explicit REL-compliant representation metadata;
   - unavailable optional representations return `404` problem details with links.
   - `/encoding` now exposes curated rights-encoding references when present.
5. Mutation endpoints now require bearer auth (`401`/`403` split) with token configuration from env or secret file only.
6. Cache refresh now uses atomic snapshot switching with locking and rollback safety.
7. Defaults hardened:
   - reload off by default,
   - no wildcard CORS defaults,
   - no default admin credentials in application/compose,
   - Fuseki image pinned and not host-published by default.
