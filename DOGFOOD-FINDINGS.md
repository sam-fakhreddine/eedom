# Dogfood Findings Log

Tracked findings from running eedom against itself during the `next` branch architecture refactoring. Each finding produces a deterministic regression test.

## Run 1: Post-P0/P1/P2.1/P4.1 (2026-04-28)

Verdict: PASS WITH WARNINGS | Security: 100/100 | Quality: 100/100

| # | Finding | Severity | Detail | Regression Test | Status |
|---|---------|----------|--------|-----------------|--------|
| D1 | OPA parse error on semgrep YAML | bug | `policies/semgrep/banned.yaml: merge error` — OPA eval `-d ./policies` includes non-Rego files | `test_opa_ignores_non_rego_files` | OPEN |
| D2 | Semgrep 2279 findings on self-scan | noise | Runs against entire repo — tests, policies, docs all scanned | `test_semgrep_respects_file_scoping` | OPEN |
| D3 | Actionability: all semgrep findings "blocked" | bug | Code findings have no fixed_version concept, so actionability classifies all as blocked upstream | `test_actionability_handles_code_findings` | OPEN |
| D4 | MI score 38/100 with 163 grade-C | info | Expected — subprocess-heavy scanner plugins have high CCN | KNOWN |
| D5 | cspell NOT_INSTALLED | env | Not installed on host — container only | N/A |
| D6 | osv-scanner skipped | env | Not installed on host — container only | N/A |

### Bugs to fix before next phase

**D1** is the highest priority — OPA is reading semgrep YAML as Rego input and failing. Fix: scope OPA's `-d` flag to `policies/policy.rego` not `./policies/`.

**D3** is a design gap — actionability was built for dependency findings (has fixed_version), not code findings (has no version concept). Fix: code findings should be classified as "actionable" by default since you can fix your own code.
