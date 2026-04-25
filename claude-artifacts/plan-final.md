# `dep-audit` Plugin — Final Implementation Plan

_Combined from phases A/B/C. See `claude-artifacts/agent-transcripts/` for sub-agent JSONL transcripts._

---

## Part A — Context & Validated Decisions

## Context

eedom already runs `syft` (SBOM), `osv-scanner` and `trivy` (vuln lookups), `scancode` (licenses), `supply-chain` (unpinned deps). Each reports findings on **direct** packages but none of them:

1. Resolve the **full transitive dependency graph** with edge metadata (runtime / build / dev / test / optional / peer).
2. Propagate a CVE **upward** through the graph and answer *"does this CVE actually reach my code, via what path, and at which layer?"*
3. Cache the resolved graph + CVE-to-package mappings **centrally** so the same `(pkg, version)` is never re-resolved across repos / CI runs.

The user wants a private, paid-tier plugin that does this — sold as the middle tier for **Firka** (proprietary agentic dev orchestrator that manages fleets of AI coding agents and enforces quality gates). Determinism target is 100%.

## User scoping decisions

- **v1 ecosystems:** Python (PyPI) + JavaScript (npm/yarn/pnpm). Java/Go/Rust are v2.
- **CVE depth, phased biggest-payoff first:**
  1. Chain propagation + edge classification (runtime/build/dev/test/optional)
  2. Symbol-level reachability (uses an AST call graph — `blast-radius` already does Python; we'd need JS)
  3. CVSS contextualization (rule-based re-scoring)
  4. Exploit-availability (CISA KEV + ExploitDB signals)
- **Location:** Separate private repo `gitrdunhq/eedom-dep-audit`, distributed as a wheel, registered via Python entry-point so eedom's `PluginRegistry` auto-discovers on install.
- **Central catalog:** Hybrid — local Postgres (port 12432, existing `package_catalog`) for self-hosted; Firka API for SaaS.

## Decision 1 — Determinism (validated, expanded)

`resolver_snapshot_id = sha256(...)` is correct in spirit but has three holes that must be closed:

1. **`psycopg_pool` does not give snapshot isolation across connections.** Pool is `min=1/max=10` (`src/eedom/data/db.py:94`). A run that touches catalog + OSV + KEV + EPSS in sequence can pick up different versions of `package_catalog` mid-scan because each `with self._pool.connection()` returns a different backend pid; default isolation is `READ COMMITTED`.
   - **Fix:** Borrow **one** connection for the whole audit run, execute `BEGIN ISOLATION LEVEL REPEATABLE READ`, pass that connection through. This is a real Postgres snapshot.
2. **OSV / npm / PyPI have no snapshot id.** The only way to get determinism is to **mirror** them into our own catalog and read exclusively from there during a run. The plugin must NOT call `osv-scanner` / PyPI live during audit — only inside a separate `eedom dep-audit refresh` verb that bumps a `vuln_index_version` row.
3. **`updated_at` in the hash is wrong granularity.** Hash the **content** (canonical JSON of semantic columns) not the row's mtime — two replays into a clean DB would otherwise differ.

**Concrete plan:**
- `RunContext` holds **one** psycopg connection in `REPEATABLE READ` for the entire run.
- New table `audit_snapshot(snapshot_id PK, vuln_index_version, kev_version, epss_version, content_hash, created_at)`.
- `snapshot_id = sha256(canonical(content_hash || vuln_index_version || kev_version || epss_version || repo_lockfile_hash))`. Wallclock not included.
- Refresh is a separate CLI verb. Audits never write to upstream-mirror tables.
- Property test asserts byte-identical findings across two runs against the same `snapshot_id`.

## Decision 2 — Schema additions (validated)

**Reuse `package_catalog` for nodes; do NOT create `dep_graph_node`.** It already has `(ecosystem, package_name, version)` UNIQUE plus `transitive_dep_count` (currently NULL), `vuln_scanned_at`, `sbom_path` (`migrations/002_package_catalog.sql:16`).

`cve_propagation` is a **real table**, not a materialized view: (a) we need to write `path_jsonb` from the plugin, (b) deterministic replay requires writing rows tied to `snapshot_id`, (c) MV refresh under REPEATABLE READ is awkward.

Migration 003 (`gitrdunhq/eedom-dep-audit/migrations/003_dep_audit.sql`):

```sql
BEGIN;

CREATE TABLE IF NOT EXISTS audit_snapshot (
  snapshot_id        TEXT PRIMARY KEY,
  vuln_index_version TEXT NOT NULL,
  kev_version        TEXT,
  epss_version       TEXT,
  content_hash       TEXT NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TYPE dep_edge_type AS ENUM
  ('runtime','build','dev','test','optional','peer');

CREATE TABLE IF NOT EXISTS dep_graph_edge (
  parent_ecosystem TEXT NOT NULL,
  parent_name      TEXT NOT NULL,
  parent_version   TEXT NOT NULL,
  child_ecosystem  TEXT NOT NULL,
  child_name       TEXT NOT NULL,
  child_version    TEXT NOT NULL,
  edge_type        dep_edge_type NOT NULL,
  snapshot_id      TEXT NOT NULL REFERENCES audit_snapshot(snapshot_id),
  PRIMARY KEY (snapshot_id, parent_ecosystem, parent_name, parent_version,
               child_ecosystem, child_name, child_version, edge_type)
);
CREATE INDEX idx_edge_child ON dep_graph_edge
  (snapshot_id, child_ecosystem, child_name, child_version);

CREATE TABLE IF NOT EXISTS cve_node_join (
  advisory_id   TEXT NOT NULL,
  ecosystem     TEXT NOT NULL,
  package_name  TEXT NOT NULL,
  version_range TEXT NOT NULL,    -- canonicalized via packaging.specifiers.SpecifierSet
  vector        JSONB,
  kev_listed    BOOLEAN NOT NULL DEFAULT false,
  epss_score    NUMERIC(5,4),
  snapshot_id   TEXT NOT NULL REFERENCES audit_snapshot(snapshot_id),
  PRIMARY KEY (snapshot_id, advisory_id, ecosystem, package_name, version_range)
);

CREATE TABLE IF NOT EXISTS cve_propagation (
  snapshot_id     TEXT NOT NULL REFERENCES audit_snapshot(snapshot_id),
  repo_name       TEXT NOT NULL,
  advisory_id     TEXT NOT NULL,
  root_ecosystem  TEXT NOT NULL,
  root_name       TEXT NOT NULL,
  root_version    TEXT NOT NULL,
  leaf_ecosystem  TEXT NOT NULL,
  leaf_name       TEXT NOT NULL,
  leaf_version    TEXT NOT NULL,
  path_jsonb      JSONB NOT NULL,
  min_edge_type   dep_edge_type NOT NULL,
  reachable       BOOLEAN,              -- NULL until phase 2 sets it
  contextual_cvss NUMERIC(3,1),         -- NULL until phase 3
  PRIMARY KEY (snapshot_id, repo_name, advisory_id, root_name, root_version,
               leaf_name, leaf_version)
);
CREATE INDEX idx_cve_prop_repo ON cve_propagation (repo_name, advisory_id);

CREATE TABLE IF NOT EXISTS kev_signals (
  cve_id    TEXT PRIMARY KEY,
  listed_at TIMESTAMPTZ NOT NULL,
  due_date  TIMESTAMPTZ,
  vendor    TEXT,
  product   TEXT
);

COMMIT;
```

Note: `peer` edge type is JS-only (PyPI has no peer concept). `transitive_dep_count` in `package_catalog` becomes a derived value the plugin backfills per snapshot.

## Decision 3 — Entry-point loading (validated)

Group: **`eedom.plugins`** (singular pluralized package, matches `src/eedom/plugins/` layout). Not `scanner_plugins` — that implies a sub-category that doesn't match the existing `PluginCategory` enum.

Upstream patch (`src/eedom/core/registry.py`, additive ~15 lines after the existing dir-scan loop at line 233):

```python
def discover_plugins(plugin_dir: Path) -> list[ScannerPlugin]:
    plugins: list[ScannerPlugin] = []
    # ... existing dir-scan loop unchanged ...

    try:
        from importlib.metadata import entry_points
        for ep in entry_points(group="eedom.plugins"):
            try:
                cls = ep.load()
                if (isinstance(cls, type) and issubclass(cls, ScannerPlugin)
                        and cls is not ScannerPlugin):
                    plugins.append(cls())
            except Exception as exc:
                logger.warning("plugin.entry_point_failed",
                               name=ep.name, error=str(exc))
    except Exception:
        logger.debug("plugin.entry_points_unavailable")

    return plugins
```

Plugin's `pyproject.toml`:
```toml
[project.entry-points."eedom.plugins"]
dep-audit = "eedom_dep_audit.plugin:DepAuditPlugin"
```

This is the **only** change to the eedom repo. Everything else lives in the private plugin repo.

---

## Part B — Layout, Delivery, Catalog, Reuse

## File Layout

**New private repo `gitrdunhq/eedom-dep-audit/`:**

```
eedom-dep-audit/
├── pyproject.toml                                 # entry-point + deps on eedom>=X
├── README.md
├── LICENSE-COMMERCIAL.txt
├── migrations/
│   └── 003_dep_audit.sql                          # DDL from Phase A
├── src/eedom_dep_audit/
│   ├── __init__.py
│   ├── plugin.py                                  # DepAuditPlugin(ScannerPlugin)
│   ├── run_context.py                             # RunContext, snapshot pinning
│   ├── snapshot.py                                # snapshot_id computation
│   ├── catalog/
│   │   ├── __init__.py
│   │   ├── protocol.py                            # CatalogBackend Protocol
│   │   ├── local_postgres.py                      # LocalPostgresCatalog
│   │   └── firka_api.py                           # FirkaApiCatalog
│   ├── graph/
│   │   ├── builder.py                             # builds dep_graph_edge from CycloneDX
│   │   ├── propagator.py                          # walks edges, classifies min_edge_type
│   │   └── edge_classifier.py                     # runtime/build/dev/test/optional/peer
│   ├── reachability/
│   │   ├── python_reach.py                        # wraps blast_radius for Python
│   │   └── js_reach.py                            # NEW: TS/JS AST → CodeGraph (phase 2)
│   ├── contextual_cvss.py                         # rule-based re-scoring (phase 3)
│   ├── exploit_signals/
│   │   ├── kev.py                                 # CISA KEV ingest (phase 4)
│   │   └── exploitdb.py                           # ExploitDB scrape (phase 4)
│   ├── refresh.py                                 # `eedom dep-audit refresh` verb
│   ├── render.py                                  # template_context override
│   └── templates/dep-audit.md.j2
└── tests/
    ├── unit/
    │   ├── test_dep_audit_plugin.py
    │   ├── test_snapshot.py
    │   ├── test_propagator.py
    │   ├── test_edge_classifier.py
    │   ├── test_local_postgres_catalog.py
    │   └── test_properties.py                     # Hypothesis class
    └── conftest.py
```

**Upstream eedom patch (one file):**
- `src/eedom/core/registry.py` — entry-point discovery (~15 lines, additive). See Phase A Decision 3.

## Phased Delivery

| Phase | Shippable outcome | New code | Migrations |
|---|---|---|---|
| **1. Chain propagation + edge classification** | "We can show every CVE, the full transitive path to it, and tag the path runtime/build/dev/test/optional." | `plugin.py`, `run_context.py`, `snapshot.py`, `graph/`, `catalog/protocol.py`, `catalog/local_postgres.py`, `refresh.py`, registry patch | `003_dep_audit.sql` |
| **2. Symbol-level reachability** | "We can mark each CVE `reachable=true/false` from app entry points using AST call graphs." | `reachability/python_reach.py` (wraps `CodeGraph.blast_radius`), `reachability/js_reach.py` (extends `graph_builder._index_javascript` for cross-file resolution) | `004_reachable_evidence.sql` adds `reachable_evidence_path TEXT` to `cve_propagation` |
| **3. CVSS contextualization** | "Each CVE gets a `contextual_cvss` adjusting base score by `min_edge_type` and `reachable`." | `contextual_cvss.py`; OPA rule additions in `policies/` (consumed but not owned by plugin) | populates `contextual_cvss` |
| **4. Exploit-availability** | "Findings are tagged `kev_listed` / `epss_score` / `exploit_pub`." | `exploit_signals/kev.py`, `exploit_signals/exploitdb.py`, `catalog/firka_api.py` | `005_epss.sql`; `kev_signals` populated |

## Pluggable Catalog Backend

```python
# src/eedom_dep_audit/catalog/protocol.py
from typing import Protocol, Iterable

class CatalogBackend(Protocol):
    def begin_snapshot(self, snapshot_id: str) -> None: ...
    def get_package(self, ecosystem: str, name: str, version: str) -> dict | None: ...
    def list_edges(self, snapshot_id: str, parent: tuple[str, str, str]) -> Iterable[dict]: ...
    def upsert_edges(self, snapshot_id: str, edges: list[dict]) -> None: ...
    def get_advisories(self, snapshot_id: str, ecosystem: str, name: str,
                       version: str) -> list[dict]: ...
    def upsert_propagation(self, snapshot_id: str, repo_name: str,
                           rows: list[dict]) -> None: ...
    def lookup_kev(self, cve_id: str) -> dict | None: ...
    def get_snapshot(self, snapshot_id: str) -> dict | None: ...
    def commit_snapshot(self, snapshot_id: str) -> None: ...
```

Two implementations:

- **`LocalPostgresCatalog(pool, conn=None)`** — wraps `psycopg_pool.ConnectionPool`. When constructed with a pre-acquired `conn`, all calls reuse that connection (the REPEATABLE READ trick from Phase A Decision 1). Fail-open like `PackageCatalog` in `src/eedom/data/catalog.py:84`.
- **`FirkaApiCatalog(base_url, api_key, http=httpx.Client)`** — REST client. `begin_snapshot` POSTs to `/v1/snapshots`, server returns the same `snapshot_id` if content matches. Same timeout/retry shape as `PyPIClient` (`src/eedom/data/pypi.py:27`). New settings on `EedomSettings`: `firka_api_url`, `firka_api_key`, `dep_audit_backend ∈ {local_postgres, firka_api}`.

## Reuse Table

| Building block | Path | Recommendation |
|---|---|---|
| `ScannerPlugin` ABC | `src/eedom/core/plugin.py:34` | **Subclass directly.** `name="dep-audit"`, `category=PluginCategory.dependency`, `depends_on=["syft"]` (needs CycloneDX SBOM produced by Syft plugin). |
| `PluginRegistry` discovery | `src/eedom/core/registry.py:233` | **Patch** — add entry-point loop (Phase A Decision 3). Only upstream change. |
| `Finding` model + dedup | `src/eedom/core/models.py:124` and `core/normalizer.py:23` | **Reuse unchanged.** Each `(advisory_id, leaf_pkg, path_hash)` becomes one Finding; severity wins via existing dedup. |
| `build_opa_input` | `src/eedom/core/policy.py:48` | **Reuse**, but extend Finding with `dep_audit_path` + `min_edge_type` fields so OPA can write `data.dep_audit.deny` rules. Remember `input.pkg`, NOT `input.package`. |
| `PackageCatalog` | `src/eedom/data/catalog.py:78` | **Wrap, don't extend.** `LocalPostgresCatalog` composes `PackageCatalog` for node lookups; new tables accessed directly via the pinned connection. |
| `package_catalog` table | `migrations/002_package_catalog.sql:16` | **Extend by reuse**, no schema changes. Plugin backfills `transitive_dep_count` per snapshot. |
| `PyPIClient` | `src/eedom/data/pypi.py:19` | **Use only inside `refresh.py`**, never inside the audit hot path. Implement `count_transitive_deps` (currently a stub returning None) as a side-effect of `refresh`. |
| `OsvScanner` | `src/eedom/data/scanners/osv.py:38` | **Reuse inside `refresh.py`** to populate `cve_node_join`. Plugin run does not invoke it. |
| `discover_packages` | `src/eedom/core/manifest_discovery.py:94` | **Reuse unchanged.** Per-package execution mode in `registry._run_all_per_package` already passes `package_root`. |
| `_build_dep_summary` | `src/eedom/agent/tools.py:129` | **Steal the purl-resolution logic into `graph/builder.py`** (depth-1 cap is wrong for us). Don't import — copy the parser, walk full depth. |
| `CodeGraph` | `src/eedom/plugins/_runners/graph_builder.py:80` | **Reuse for phase 2.** `python_reach.py` calls `CodeGraph(db_path=":memory:")`, then `index_directory()`, then `blast_radius(symbol, max_depth)` per CVE-affected symbol. JS path needs new resolver. Signature confirmed: `blast_radius(symbol_name: str, max_depth: int = 3) -> list[dict]` at `graph_builder.py:163`. |
| `EvidenceStore` | `src/eedom/data/evidence.py:21` | **Reuse unchanged.** Audit writes JSONL evidence per snapshot at `evidence/{commit_sha}/{snapshot_id}/dep-audit.jsonl`. |
| `EedomSettings` | `src/eedom/core/config.py:41` | **Extend** with `dep_audit_backend`, `firka_api_url`, `firka_api_key`, `dep_audit_max_depth` (default 25). Respect existing `scanner_timeout=60s` for refresh; audit reads from DB so should be sub-second. |

---

## Part C — Tests, Risks, Verification

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
