# `dep-audit` Plugin — Phase C: Tests, Risks, Verification

## Test Plan

**Property domains from CLAUDE.md DPS-12 that apply** (group in `tests/unit/test_properties.py` as `class TestProperties`, one method per domain, each with `@given` decorator):

- **Determinism / INVARIANT** — same inputs → same output
- **Idempotency / INVARIANT** — running refresh twice produces same catalog state
- **Monotonicity / SAFETY** — contextual severity never moves backward when a path is reclassified runtime
- **Boundedness / PERFORMANCE** — propagation paths and runtime stay finite under graph growth
- **Atomicity / SAFETY** — partial snapshot state never visible to readers
- **Integrity / SAFETY** — tampered catalog rows fail snapshot hash verification

Skipping (not at this boundary): Confidentiality (no secrets), Linearity (no tokens), Reversibility (audits are read-only; refresh is idempotent).

### Three concrete property tests

1. **`test_audit_is_deterministic`** — Domain: **Determinism / INVARIANT**.
   ```python
   @given(graph=dep_graph_strategy(), advisories=advisory_strategy())
   @settings(max_examples=200)
   def test_audit_is_deterministic(self, graph, advisories):
       # Build fixture catalog from generated graph + advisories
       # Compute snapshot_id, run DepAuditPlugin.run() twice
       # Assert sha256(canonical(findings_a)) == sha256(canonical(findings_b))
   ```
   Maps to "Same inputs → same output."

2. **`test_propagation_path_length_bounded`** — Domain: **Boundedness / PERFORMANCE**.
   ```python
   @given(graph=dep_graph_strategy(max_depth=50, max_nodes=500))
   def test_propagation_path_length_bounded(self, graph):
       # Assert every cve_propagation.path_jsonb has length <= settings.dep_audit_max_depth
       # Assert audit completes in < pipeline_timeout=300s (from core/config.py:41)
   ```
   Maps to "Resources stay within finite limits."

3. **`test_severity_monotonic_under_propagation`** — Domain: **Monotonicity / SAFETY**.
   ```python
   @given(base_advisory=cvss_strategy(), edge_chain=edge_type_chain())
   def test_severity_monotonic(self, base_advisory, edge_chain):
       # Assert contextual_cvss(advisory, runtime_chain) >= contextual_cvss(advisory, dev_chain)
       # Once a path is classified runtime, contextual severity never drops below dev/test
   ```
   Maps to "State never moves backward."

### Standard unit tests

- `test_dep_audit_plugin.py` — `name`, `description`, `category`, `depends_on=["syft"]`; `can_run` returns True iff a CycloneDX SBOM exists from syft; `run` returns typed `PluginResult` on happy path; returns `PluginResult(error=...)` on catalog unreachable (fail-open).
- `test_edge_classifier.py` — pyproject groups, requirements.txt extras, package.json `dependencies` vs `devDependencies` vs `peerDependencies` vs `optionalDependencies`, pnpm workspace edges.
- `test_local_postgres_catalog.py` — integration test using existing test container pattern. **Tests MUST run in container** per CLAUDE.md (`make test`). Port 12432.
- `test_registry_entry_point.py` — verifies `discover_plugins` finds plugins registered via `eedom.plugins` entry-point group, tolerates missing entry-points module, logs but doesn't crash on broken plugin classes.
- `test_snapshot.py` — given identical canonical inputs → identical `snapshot_id`; given any differing input → different `snapshot_id`; wallclock not in hash.

### Annotation

Add `# tested-by: tests/unit/test_dep_audit_plugin.py` to top of `plugin.py` (CLAUDE.md convention).

## Risks

- **Snapshot drift on shared Postgres.** If a `refresh` runs concurrently with an audit, the audit's REPEATABLE READ snapshot will hold rows the refresh hasn't yet touched, but writes on `cve_propagation` could conflict. **Mitigation:** refresh acquires `LOCK TABLE cve_node_join IN EXCLUSIVE MODE` and bumps `vuln_index_version` atomically; audits never write to `cve_node_join`.
- **OSV version-range parsing.** Storing `version_range TEXT` requires deterministic equality. **Mitigation:** canonicalize via `packaging.specifiers.SpecifierSet` (Python) and `semver.Range` equivalent (JS) before insert.
- **JS edge classification ambiguity.** pnpm `peerDependencies` are sometimes runtime, sometimes optional. **Mitigation:** ship per-ecosystem classifier with documented rules; expose `--strict-edge-classification` flag.
- **Symbol reachability in monkeypatched Python and dynamic JS.** False negatives are likely. **Mitigation:** phase 2 ships with `reachable IS NULL` meaning "unknown" rather than `false`. Only `reachable=true` triggers OPA escalation; `NULL` is treated conservatively as "potentially reachable."
- **Firka API tier requires network — non-deterministic against a moving server.** **Mitigation:** SaaS responses include the server's `snapshot_id` and the plugin verifies it matches the locally computed one before using rows.
- **License: this plugin is private.** Need a license-key check on `DepAuditPlugin.__init__()` that no-ops the plugin (returns empty findings) when unlicensed, with a clear log line. Don't crash on missing license — fail-open per eedom convention.

## Explicit non-goals (v1)

- Java (Maven/Gradle), Go modules, Rust crates — phase 5+.
- Container image scanning — Trivy plugin already covers it.
- Live CVE feed subscriptions — refresh is pull-based on a cron, not push.
- License-incompatible-transitive detection — separate plugin.
- Auto-fix / version bump suggestions — Firka orchestrator territory.
- SBOM generation — relies on existing `syft` plugin output (`depends_on=["syft"]`).
- Cross-org propagation insights — single-tenant only in v1.

## Verification (end-to-end)

1. **Unit + property tests:** `make test` (in container per CLAUDE.md).
2. **Lint + format:** `make quality-check` (`uv run ruff check`, `uv run black`).
3. **OPA policy tests** for any new Rego rules: `opa test policies/`.
4. **Self-scan (dogfood):** `make dogfood` — eedom scans itself with the plugin enabled (after the plugin wheel is `pip install -e .` into the eedom env).
5. **Determinism check:** run audit on a fixture repo twice, diff JSONL outputs — must be byte-identical.
6. **Refresh isolation check:** start a long-running audit on snapshot N; concurrently run `eedom dep-audit refresh`; confirm audit completes against snapshot N (not N+1) and produces the same findings as a third audit run pinned to N.
7. **Backend swap check:** run the same audit with `dep_audit_backend=local_postgres` and `dep_audit_backend=firka_api` (mock server returning identical rows); findings must be identical.

## Critical Files (for the implementer)

- `src/eedom/core/registry.py` — the **one** upstream patch (entry-point discovery)
- `src/eedom/core/plugin.py` — ABC the plugin subclasses
- `src/eedom/data/catalog.py` — wrapped by `LocalPostgresCatalog`; identity & fail-open semantics
- `migrations/002_package_catalog.sql` — existing schema being extended by `003_dep_audit.sql`
- `src/eedom/plugins/_runners/graph_builder.py` — reused for phase-2 reachability via `CodeGraph.blast_radius`
- `src/eedom/data/db.py:94` — `psycopg_pool.ConnectionPool(min_size=1, max_size=10, open=True)` — borrow one connection for the run
- `src/eedom/core/config.py:41` — `EedomSettings`, extend with dep-audit settings
- `src/eedom/core/policy.py:48` — `build_opa_input`, remember `input.pkg`
