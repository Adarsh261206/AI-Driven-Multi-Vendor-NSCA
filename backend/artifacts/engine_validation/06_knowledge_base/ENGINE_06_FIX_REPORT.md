# ENGINE_06_FIX_REPORT — Knowledge Base / Training Mapping (§10.6, §9.2, §14.1, §14.3, §15.1–15.3, §12)

**Verdict: PASS.** Engine 06 is fixed and revalidated. No Engine 07 work was started.

## 1. What changed

Implemented one shared contract in `backend/app/ai/kb_domain.py` and made all three
implementations obey it:

- Canonical identity is lowercased/stripped vendor and platform plus stripped raw syntax
  (`kb_domain.py:128`).
- `lookup()` is exact, total, and deterministic: hostile argument types are a miss, never
  a crash; duplicate rows cannot persist because of
  `uq_semantic_mappings_identity_version` plus earliest-row tiebreaks.
- Similarity is suggestion-only via `lookup_suggestions()`; it never stores or serves
  another command’s meaning.
- A real `universal_model_path` is required before persistence. The Pydantic create schema
  still permits an incomplete proposal object, but the service/domain layer rejects a
  missing/invalid path with a typed validation error mapped to HTTP 422.
- Trust requires both confirmation and confidence ≥ 0.7 (`kb_domain.py:53,381-389`).
- POST defaults to an unconfirmed proposal at 0.5 confidence; an explicit administrator
  assertion stores confirmed/1.0. Explicit `CONFIRM` promotes to 1.0 only when no estimate
  is supplied. `EDIT` never confirms and never fabricates confidence. `REJECT` retains,
  unconfirms, versions, and prefixes notes with `REJECTED:`.
- Every real mutation appends one post-change version snapshot through the shared builder
  (`kb_domain.py:347`); no-op writes append nothing.
- Pagination rejects hostile values and caps explicit limits at 5000
  (`kb_domain.py:85,276-289`).
- Quality scoring uses one domain function with four recorded-fact axes in the in-memory
  store, SQL store, and API path (`kb_domain.py:399-463`).

Intentional layer distinction: store `create()` is idempotent and merges an exact
duplicate in place; HTTP `POST /training/mappings` returns 409 for an exact duplicate.
Both preserve one canonical row.

## 2. F1–F17 disposition

| ID | Finding | Status | Key evidence |
|---|---|---|---|
| F1 | KB unwired from normalization/semantic/adaptive reanalysis | FIXED | `normalization.py:367,514-586`; V06-59/60/85/86/88; V05-85; sweep |
| F2 | Three divergent implementations | FIXED | shared `kb_domain.py`; V06-68–74,106; store/API duplicate distinction |
| F3 | Edit confirms | FIXED | V06-17/34/71; sweep C4 |
| F4 | Lookup not total / crashes | FIXED | V06-01/31/41/53/79/80; sweep C1 |
| F5 | Fuzzy absorption / wrong meaning | FIXED | V06-15/16; sweep C9/C10, 0 fuzzy, 0 collisions |
| F6 | No administrator requirement | FIXED | `training.py` admin-gated routes; V06-52 |
| F7 | Untrustworthy version history | FIXED | shared version builder; V06-18/45/50/68; migration preserves history |
| F8 | Schema drift from §15.1/§12 | FIXED | `models/__init__.py:297-337`; migration 005 |
| F9 | Unvalidated content at entry points | FIXED | real model-path validation; typed errors; V06-27–31/42/43/82/83/97–105 |
| F10 | Dead confidence / no review routing | FIXED | proposal default, assert/confirm rules, review queue; V06-39/48/58/63–65/89 |
| F11 | No §15.3 quality scoring | FIXED | same domain scoring in all layers; V06-62/106 |
| F12 | Trailing-whitespace orphan rows | FIXED | canonical strip; V06-30/78 |
| F13 | Inconsistent filters | FIXED | literal canonical filters; V06-36/73/79/80/101/105 |
| F14 | Unstable ordering | FIXED | canonical ordering; naive UTC timestamps; V06-91–93; sweep C8 |
| F15 | Hard-coded relevance | FIXED | relevance derived from mapping path; V06-55/56 |
| F16 | Quadratic create | FIXED | indexed exact identity; V06-94/95/96; sweep performance |
| F17 | Hostile input reaches driver | FIXED | NUL/control, size, type, bound guards; V06-97–105; sweep C1 |

## 3. Evidence

### 3.1 Targeted E06 validation

Command:

```powershell
venv\Scripts\python.exe -m pytest tests/validation/test_v06_knowledge_base.py -q -p no:randomly -W ignore --tb=short -rf
```

Result: **106 passed, 0 failed** — including new three-way quality conformance row V06-106.

Pre-fix baseline: 105 evidence rows, 47 PASS / 58 FAIL; classifications 47 CONFIRMED
BEHAVIOR, 18 BUG, 18 DESIGN LIMITATION, 16 MISSING, 6 RECOMMENDATION.
Post-fix hypotheses: **H06-01–H06-30 all REJECTED**; corpus contract checks PASS with
0 violations.

Related suites:

```powershell
venv\Scripts\python.exe -m pytest tests/validation/test_v05_normalization.py -q -p no:randomly -W ignore
```

Result: **108 passed**. V05-85 was rewritten because E06 supersedes its old “no knowledge
base exists” premise: the test now proves the KB is optional, never fabricated, and only
confirmed/trusted/path-valid/coercible hits affect normalization.

### 3.2 Corpus sweep

Command:

```powershell
venv\Scripts\python.exe scripts\engine_validation\sweep_knowledge_base.py
```

Result: exit 0, contract verdict PASS, 0 violations across C1–C10.

Observed corpus facts:

- 480 files seen; 479 ingested.
- 20,420 lines resolved through the real deterministic normalizer to real model paths.
- 11,532 lines recorded as unmapped and not invented into the KB.
- 20,420 rows created; 0 exact/fuzzy absorption anomalies; 0 lookup collisions;
  0 lookup misses.
- 114 cross-vendor isolation queries, 0 breaches.
- Deterministic rebuild ordering verified.
- Per-create p50 0.1321 ms, p95 0.1753 ms, max 0.2596 ms; total file-load sum 2876.4 ms.

Artifacts:

- `backend/artifacts/engine_validation/06_knowledge_base/dataset_results.csv`
- `backend/artifacts/engine_validation/06_knowledge_base/dataset_summary.json`
- `backend/artifacts/engine_validation/06_knowledge_base/contract_results.json`

### 3.3 Migration 005 execution

Command:

```powershell
venv\Scripts\python.exe scripts\engine_validation\validate_migration_005.py
```

Result: **18/18 checks PASS**, executed only against throwaway database
`engine_validation_test`.

Validated:

- 001→004 baseline, legacy inserts, 004→005 upgrade, 005→004 downgrade, 004→005 round trip.
- Legacy reconciliation: case/whitespace duplicates merged with earliest row surviving;
  version rows reassigned, none deleted; FLOAT confidence preserved as NUMERIC(5,2);
  NULL model paths backfilled to `""`; UUID actors converted to VARCHAR(100).
- Final schema has non-null model paths, NUMERIC(5,2) confidence, VARCHAR actors, no
  users FK on KB tables, and `uq_semantic_mappings_identity_version`.
- This validation found and fixed a real 005 downgrade bug: the USING expression
  referenced the pre-rename column name. Downgrade now converts type before renaming.

Artifact:

- `backend/artifacts/engine_validation/06_knowledge_base/migration_results.json`

### 3.4 Report generation

Command:

```powershell
venv\Scripts\python.exe scripts\engine_validation\report_knowledge_base.py
```

Generated:

- `test_results.csv`
- `summary.json`
- `performance.csv`
- `determinism_results.csv`
- `security_results.csv`

Known index limitation: 38 generic conformance rows remain outside the 30-hypothesis
reference index. That unreferenced set is unchanged from the pre-fix baseline.

### 3.5 Full regression

Command:

```powershell
venv\Scripts\python.exe -m pytest -q -p no:randomly -W ignore --tb=line -rf
```

Result: **1287 passed, 22 failed**.

The 22 failures are the exact 21 pre-existing failures documented in
`ENGINE_05_FIX_REPORT.md` — benchmark_execution 6, juniper_benchmark 7, frontend 2,
phase8 6 — plus `test_v01_65_postfix_ingest_performance`.

V01-65 is an Engine 01 latency measurement, not an E06 functional failure: the 9.9 MiB
ingest shape measured p50 620.596 ms against a 104.914 ms baseline threshold while all
functional E01 rows passed. This E06 change does not touch ingestion.

Verification note: isolated V01 reruns briefly left
`01_ingestion/raw_results.jsonl` containing only V01-65. I repaired that artifact by
rerunning the full E01 validation suite: **97 passed, 1 failed**, restoring 98 evidence
rows.

## 4. E06 files changed

Production:

- `backend/app/ai/kb_domain.py`
- `backend/app/ai/knowledge_base.py`
- `backend/app/repositories/knowledge_base.py`
- `backend/app/api/v1/training.py`
- `backend/app/ai/adaptive.py`
- `backend/app/ai/semantic.py`
- `backend/app/engines/normalization.py`
- `backend/app/ai/validators.py`
- `backend/app/models/__init__.py`
- `backend/app/schemas/__init__.py`
- `backend/alembic/versions/005_kb_contract.py`

Validation/evidence:

- `backend/tests/validation/test_v06_knowledge_base.py`
- `backend/tests/validation/test_v05_normalization.py`
- `backend/tests/test_ai_integration.py`
- `backend/scripts/engine_validation/sweep_knowledge_base.py`
- `backend/scripts/engine_validation/report_knowledge_base.py`
- `backend/scripts/engine_validation/validate_migration_005.py`
- `backend/artifacts/engine_validation/06_knowledge_base/`

No commits were made. The working tree already contained unrelated Engine 01–05
modifications; the E06 change set is limited to the files above.

## 5. Remaining limitations

- No dedicated HTTP quality-score endpoint; quality is computed by the stores/workflow
  through the shared domain function.
- The create DTO still allows an incomplete proposal object; persistence always enforces
  the required model path and actor with typed errors.
- E05 remains upstream context only; this report does not claim E05 is fixed.
