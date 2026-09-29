# ENGINE_READINESS_SUMMARY - Engine 06 - Knowledge Base (spec 10.6)

**Scope:** `backend/app/ai/knowledge_base.py`, `backend/app/repositories/knowledge_base.py`,
`backend/app/api/v1/training.py`, `backend/app/ai/adaptive.py` +
`app/models` (`semantic_mappings` / `mapping_versions`) and migration 001 +
their contract with `docs/PROJECT_MASTER_SPEC.md` (§10.6, §9.2, §14.1, §14.3, §15.1,
§15.2, §15.3, §12 interface) and the consumers the contract names
(`app/engines/normalization.py`, `app/ai/semantic.py`)
**Evidence:** 105 pytest rows (105 passed, 0 failed) - 480-file corpus (3-pass sweep) -
1 runtime probe suite - 0 production files modified
**Overall verdict:** **FAIL** (nothing reads the KB, three disagreeing implementations,
edit-confirms, crashing lookups, no admin role - not read speed or state determinism)
**Date:** 2026-09-25

---

## Scoreboard

| Status | Count | % |
|---|---|---|
| PASS | 47 | 45% |
| PARTIAL | 0 | 0% |
| FAIL | 58 | 55% |
| **Total** | **105** | 100% |

| Classification | Count |
|---|---|
| CONFIRMED BEHAVIOR | 47 |
| BUG | 18 |
| DESIGN LIMITATION | 18 |
| MISSING | 16 |
| RECOMMENDATION | 6 |

| Category | Rows | Status |
|---|---|---|
| A spec schema / §15.1 + §12 | 8 | PASS 3, FAIL 5 |
| B in-memory KnowledgeBase | 17 | PASS 12, FAIL 5 |
| C KnowledgeBaseRepository | 13 | PASS 6, FAIL 7 |
| D REST API (`training.py`) | 18 | PASS 10, FAIL 8 |
| E workflow (§9.2 / §14.3 / §15.3) | 10 | PASS 4, FAIL 6 |
| F drift: in-memory vs repo vs API | 8 | PASS 0, FAIL 8 |
| G SEPARATE RECORD - wrong/unsupported vendor | 7 | PASS 4, FAIL 3 |
| H semantic fidelity of meanings | 3 | PASS 1, FAIL 2 |
| I pipeline integration (§9.2 / §10.6) | 6 | PASS 1, FAIL 5 |
| J determinism | 3 | PASS 2, FAIL 1 |
| K performance (measurement only) | 3 | PASS 2, FAIL 1 |
| L hostile / boundary input | 9 | PASS 2, FAIL 7 |

---

## Hypotheses (26 CONFIRMED - 4 REJECTED - 0 unverifiable)

CONFIRMED: H06-01 no UNIQUE constraint -> lookup crashes on duplicates - H06-02 schema
drifts from §15.1/§12 (nullable path, FLOAT, UUID, `created_by` missing from response) -
H06-03 fuzzy absorption stores the wrong syntax/meaning - H06-04 **edit confirms** in both
storage layers - H06-05 no version record at creation (2 of 3 paths) - H06-06 REJECT is a
no-op on confirmed rows (adaptive) / divergent elsewhere - H06-07 missing actor ->
raw `IntegrityError` - H06-08 trailing-space row permanently unreachable - H06-09 lookup
is implementation-specific (dead `fuzzy_lookup`, fuzzy vs exact) - H06-10 silent list
truncation at 100 - H06-11 case-mismatch duplicates accepted then crash - H06-12 **no
admin role on any training endpoint** - H06-13 content unvalidated (model path, empty
syntax, empty meaning) - H06-14 phantom version on no-op PUT, none on REJECT - H06-15
KB hypothesis hardcodes relevance `medium` - H06-16 §9.2 step 5 absent (no re-run) -
H06-17 §15.3 quality scoring absent - H06-18 AI confidence never stored/filtered/routed -
H06-19 implementations drift on version content, create records, dedup - H06-20 two
unrelated `TrainingMapping` classes - H06-22 case + `%` filters change lookup and crash
multi-row matches - H06-23 KB unwired (normalization/semantic/adaptive) - H06-24
re-analysis hardcodes `CiscoIOSParser` - H06-25 stats/list order not deterministic -
H06-27 `create()` quadratic (5,000 rows = 16.7 s) - H06-28 hostile input reaches the
driver (NUL, 1 MiB, negative limit, non-string).

REJECTED: H06-21 "mappings leak across vendors" (exact hit / miss in all 3 impls +
**408 cross-vendor corpus queries, 0 breaches**) - H06-26 "identical sequences produce
different state" (state reproducible in memory and over Postgres; only *ordering*
varies) - H06-29 "SQL injection works" (parameterized statements) - H06-30 "offline KB
fallback doesn't work" (§14.3.5 hypothesis served without an LLM).

---

## Blocking findings (must be fixed before this engine is ready)

1. **F1 - The §10.6 duty is unwired: nothing that normalizes or analyzes reads the
   KB.** `normalization.py` and `semantic.py` have no knowledge-base import; §9.2 step 5
   ("re-run normalization and compliance with the new mapping") has no implementation -
   confirming a mapping changes nothing downstream; `AdaptiveLearningEngine` has no caller
   outside tests. The store is populated but unread (upstream context: Engine 05's
   V05-85 - cited, not re-tested).
2. **F2 - One logical contract, three divergent implementations.** Lookup: in-memory
   fuzzy >0.8 vs repository exact-only (same query -> `True` vs `False`); the repository's
   own `fuzzy_lookup` has zero callers. Version content: API records post-change, both
   storage layers record **pre-change**. Create: API writes a v1 record, storage layers
   write none. Duplicate: API 409 / in-memory silent overwrite / near-dup absorbed vs
   accepted. List: API pages with total, repository truncates at 100 silently, in-memory
   returns all. Reject: API unconfirms+annotates, adaptive deletes only unconfirmed,
   storage layers have no reject. Two unrelated classes share the name `TrainingMapping`.
3. **F3 - Editing confirms the mapping (admin gate bypassed).** In-memory
   `update()` (:239-241) and repository `update()` (:189-191) both force
   `admin_confirmed=True, confidence=1.0` on any edit - probe: adding an admin note takes
   `(False, 0.5, 1) -> (True, 1.0, 2)`. §9.2 step 3 defines CONFIRM/EDIT/REJECT as
   distinct and §14.3.3 requires human approval; the API PUT layer behaves correctly,
   both storage layers underneath it do not.
4. **F4 - Lookup is not total: it crashes with HTTP 500.** No `UNIQUE(vendor, platform,
   raw_syntax, version)` anywhere (§15.1 requires it); the API's duplicate check is
   case-sensitive while lookup is `ilike`, so `cisco` + `Cisco` with the same syntax
   creates two rows and the next lookup raises `MultipleResultsFound`;
   `lookup('%','%','show version')` matches every vendor through unescaped `ilike` and
   crashes the same way; `GET ?vendor=cisco` cannot see a row stored as `Cisco`.
5. **F5 - Fuzzy absorption corrupts the knowledge stored.** A distinct line at Jaccard
   0.875 is absorbed into a neighbour (its syntax discarded, the neighbour's meaning
   overwritten); a query at 0.833 returns a *different command's* mapping. On the real
   corpus: **216 of 31,952 lines (0.68%) absorbed, worst file 56.5%**
   (`Juniper\Firewalls\SRX\juniper_firewall`, 26/46 lines). Latent only because F1 means
   nothing reads it yet.
6. **F6 - No administrator requirement on any training endpoint.** All 8 endpoints use
   `get_current_user` only; `require_admin`/`require_auditor` exist (`auth.py:145-146`)
   and sibling routers use them, but §10.6/§14.1 reserve create/confirm/reject to the
   administrator. Any authenticated user can confirm mappings - combined with F3, push a
   mapping to `admin_confirmed=True, confidence=1.0`.

Secondary: **F7** version history untrustworthy (no create record, phantom no-op PUT
version, unversioned REJECT, pre-vs-post snapshots, `IntegrityError` on missing actor) -
**F8** schema drift (nullable `universal_model_path`, FLOAT confidence, UUID `created_by`,
`created_by` absent from the API response) - **F9** content unvalidated at every entry
point (bogus model path, empty syntax/meaning, 1 MiB `raw_syntax`) - **F10** confidence is
dead data (POST hardcodes 1.0, schemas have no confidence field, no filter, no REVIEW
routing for §14.3.2) - **F11** §15.3 quality scoring absent - **F12** trailing-space row
unreachable - **F13** filter interpretation inconsistent (case, `%`) - **F14** stats/list
order nondeterministic (3/3 runs differ) - **F15** hardcoded `medium` relevance and
hardcoded `CiscoIOSParser` in re-analysis - **F16** quadratic `create()` (14.1x time for
4x input) - **F17** NUL/`limit=-1`/51-char vendor/non-string syntax reach the driver as
raw `DBAPIError`/`AttributeError` -> HTTP 500.

---

## What is solid

Vendor/platform isolation (**408 cross-vendor corpus queries, 0 breaches**; exact hit /
miss identical in all three implementations; unknown vendors accepted) - lookup basics
(hit/miss, case-insensitive vendor/platform, whitespace tolerance) - the REST lifecycle
*as exposed* (POST v1+record, 409 dedup, PUT does not confirm and records the change,
confirm sets everything + audit row, reject unconfirms + audit row, trust fields not
client-settable, VARCHAR(50) enforced) - offline §14.3.5 fallback (KB-served hypothesis
with no LLM) and the §14.3.4 audit trail - deterministic state over memory and Postgres -
fast reads (0.09 ms in-memory / 0.8 ms repository lookup) - parameterized queries (SQL
injection inert) - typed errors for unknown ids, working list/count/stats filters.

## Corpus measurements (480 files - 479 ingested - 31,952 lines)

| Measure | Value |
|---|---|
| absorption | **216 lines (0.68%)** - 0 exact, 216 fuzzy; per-label juniper 2.0%, paloalto 1.0%, fortinet 0.9%, cisco 0.5% |
| lookups after ingestion | 31,736 exact hits, **216 collisions** (= absorbed lines now answer with a different syntax/meaning), 0 misses |
| worst files | `Juniper\Firewalls\SRX\juniper_firewall` **26/46 (56.5%)** - `juniper_vlan` 2/10 - `mpls-infrastructure\bgp-config.j2` and `Routers\MPLS\bgp-config.j2` 8/50 - `configs_junos-srx-1.cfg` 15/115 - `juniper_syslog` 11/92 |
| cross-file, same vendor | cisco duplicate files 120/120 exact - juniper 82 exact / 38 miss - fortinet 14 exact / 106 miss - **0 fuzzy wrong-meaning hits** |
| cross-vendor (separate record) | 136 rows x 3 foreign labels = **408 queries, 0 breaches**, 18.7 ms |
| timing | load 4,679.8 ms sum, 37.4 ms max/file, 0.31 ms max/create; sweep 5.48 s (3 passes) |
| skipped | 1 file (`fork-config.cfg`) contained 0 eligible lines |

Caps: 120 lines / 200 chars per file (per-file KBs, so absorption is measured within a
file; the quadratic write cost is measured separately - see below). Directory labels are
hints used only to choose content; no detection accuracy is claimed.

## Performance (measurement only)

Corpus ingestion: p50 **0.102 ms** / p95 **0.211 ms** / max **0.311 ms** per create.
Reads: 1,000 in-memory lookups **77 ms** (probe) / 87 ms (test) = 0.08 ms each; 200
repository lookups **164 ms** = 0.8 ms each (only `ix_semantic_mappings_vendor_platform`;
`raw_syntax` unindexed). Writes: `KnowledgeBase.create` 200 = 22 ms, 800 = 309 ms
(**14.1x for 4x input**), 5,000 = **16.7 s** - O(n^2) dedupe scan over every existing
row.

## Regression / integrity

- Full suite before E06: 845 collected / 819 passed / 26 failed -> after: **950 / 924 /
  the same 26 pre-existing failures** (105 new tests). Failure composition unchanged:
  `test_benchmark_execution` 6, `test_detection` 2, `test_frontend_integration_support`
  2, `test_juniper_benchmark` 7, `test_phase5_integration` 2, `test_phase8_hardening` 6,
  `test_vertical_slice` 1.
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/`
  **empty**; working tree matches the recorded pre-existing baseline.
- New files only: `tests/validation/test_v06_knowledge_base.py`,
  `scripts/engine_validation/{sweep,report}_knowledge_base.py`,
  `artifacts/engine_validation/06_knowledge_base/*`, plus the conftest engine mapping for
  `06_knowledge_base`.
- Engine 05 treated as **upstream context only** per the user's directive - cited where
  it touches a §10.6 duty (V06-85 vs V05-85), never assumed fixed, not re-tested.

## NOT APPLICABLE / NOT VERIFIABLE

ML quality (deferred) - effect of a confirmed mapping on live compliance outcomes (F1:
no live consumer - MISSING, not measured; Engines 07/11 own downstream) - §15.3 scoring
correctness (not implemented) - concurrency/locking/transactions (all probes
single-threaded) - authorization penetration testing (F6 established from route source,
no live token abuse, no CVE scan) - whether the 0.8 similarity threshold is *right* (no
ground truth exists; its consequences are measured) - Postgres performance beyond the
one measured index.

## Limitations of this validation

Sweep caps keep each pass-1 KB at <=120 rows - a single store over all 31,952 lines would
show more collisions and quadratic build time (not attempted for runtime reasons);
"absorbed" is the KB's own dedupe verdict, not human ground truth for true duplicates;
category G uses labels only to choose content; comparisons run in one process against one
throwaway database (`engine_validation_test`); performance numbers are single-machine
measurements, not a readiness score; hypothesis conclusions derive only from the recorded
evidence rows.

---

**Readiness:** NOT READY - 6 blocking findings (F1, F2, F3, F4, F5, F6).
**Next:** Engine 07 (pending user approval).
