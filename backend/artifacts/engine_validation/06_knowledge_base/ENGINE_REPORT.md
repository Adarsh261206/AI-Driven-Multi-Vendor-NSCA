# Engine 06 - Knowledge Base (spec 10.6)

**Evidence:** 105 pytest rows (105 passed, 0 failed) + 480-file corpus sweep (3 passes) +
1 runtime probe suite + report CSVs
**Date:** 2026-09-25
**Verdict:** **FAIL - NOT READY**

---

## 1. Method

Ground rules (user-mandated, unchanged from Engines 01-05):

- No production code was modified. Only `backend/tests/validation/**`,
  `backend/scripts/engine_validation/**` and `backend/artifacts/engine_validation/**`
  were written. `git diff -- backend/app/` is empty.
- Detector output is **not** used as ground truth. Category G is the separate,
  explicitly-labelled record of wrong/unsupported-vendor consequences, per the
  methodology rule.
- Every number in this report is recomputed from code, from the pytest evidence rows, or
  from the sweep/probe artifacts. Report prose is never treated as evidence.
- Statuses report whether the **requirement** is met: `FAIL` means the defect is present.
  Test rows therefore assert the defect (`assert defect`) for defect claims and
  `assert ok` for conformance claims.
- No numeric readiness score is produced. Verdicts are PASS / PARTIAL / FAIL /
  NOT VERIFIABLE / NOT APPLICABLE.
- Hypotheses are phrased as **defect claims**; `CONFIRMED` if any linked evidence row is
  FAIL/PARTIAL, otherwise `REJECTED`.

Pipeline order for this engine: INSPECT -> CONTRACT -> INDUSTRY EXPECTATIONS -> TEST ->
DATASET -> SECURITY -> REPORT -> STOP.

**Explicit user directive for this engine:** Engine 05 findings are carried as *upstream
context only*. They are cited where they touch a section 10.6 duty (e.g. the normalizer
never calling the knowledge base) and are **never assumed fixed**; nothing in this report
claims an Engine 05 result as this engine's evidence, and Engine 05's own defects are not
re-litigated here.

## 2. Contract under test

| Source | Clause used as the expectation |
|---|---|
| `docs/PROJECT_MASTER_SPEC.md:512-524` | **§10.6 Knowledge Base** - "Provide lookup for normalization", "Administrator updates mappings", training lifecycle `suggest -> confirm/edit -> reject`, mappings quality-scored for reuse |
| `docs/PROJECT_MASTER_SPEC.md:405-441` | **§9.2 loop** - 1 lookup normalization results, 2 reuse confirmed mappings/ask AI, 3 present to administrator (CONFIRM / EDIT / REJECT), 4 version the mapping, 5 re-run normalization + compliance with the new mapping |
| `docs/PROJECT_MASTER_SPEC.md:871-885` | **§12 interface** `TrainingMapping {id, vendor, platform, raw_syntax, semantic_meaning, universal_model_path, confidence, admin_confirmed, admin_notes, version, created_by, created_at}` (non-null model path, confidence "estimated, not fabricated") |
| `docs/PROJECT_MASTER_SPEC.md:1021-1027` | **§14.1** administrator confirms/rejects, "Estimate confidence", "Threshold enforcement" |
| `docs/PROJECT_MASTER_SPEC.md:1041-1047` | **§14.3 AI safety** - 14.3.2 "Low confidence triggers REVIEW, not PASS/FAIL"; 14.3.3 human-in-the-loop approval; 14.3.5 fallback when no LLM is configured |
| `docs/PROJECT_MASTER_SPEC.md:1075-1105` | **§15.1 DDL** - `UNIQUE(vendor, platform, raw_syntax, version)`, NOT NULL columns, `VARCHAR(50)` vendor / `VARCHAR(100)` created_by, `DECIMAL(5,2)` confidence |
| `docs/PROJECT_MASTER_SPEC.md:1107-1123` | **§15.2 flow** - duplicate check, append a version record on **every** change with `changed_by` NOT NULL |
| `docs/PROJECT_MASTER_SPEC.md:1125-1131` | **§15.3 quality axes** - admin confirmations, consistency across similar configs, age/version history, AI confidence at creation |
| Internal consistency | one logical contract must behave the same in every implementation that exposes it; CONFIRM / EDIT / REJECT are three distinct administrative actions |

Files in scope: `app/ai/knowledge_base.py` (296 lines, in-memory store),
`app/repositories/knowledge_base.py` (296 lines, PostgreSQL store),
`app/api/v1/training.py` (454 lines, REST surface), `app/ai/adaptive.py` (283 lines,
workflow layer), `app/models/__init__.py:291-311` + `mapping_versions`,
`alembic/versions/001_initial_migration.py:204-219`, `app/schemas/__init__.py:341-373`,
plus the consumers the contract names: `app/engines/normalization.py`,
`app/ai/semantic.py`.

## 3. What the knowledge base actually does (observed)

- **Four layers, one contract.** `app/ai/knowledge_base.py` (in-memory
  `KnowledgeBase` + `TrainingMapping` dataclass), `app/repositories/knowledge_base.py`
  (`KnowledgeBaseRepository` over `semantic_mappings` / `mapping_versions`),
  `app/api/v1/training.py` (REST on top of the repository) and `app/ai/adaptive.py`
  (a workflow layer that reads/writes the repository). All four answer the same
  questions - lookup, create, list, confirm, reject - and they do not agree (section 9,
  F2).
- **In-memory lookup**: exact vendor/platform/syntax match first, then a fuzzy fallback
  returning the first mapping with Jaccard similarity > 0.8
  (`knowledge_base.py:120-131`). `create()` dedupes by calling that lookup, so a
  distinct-but-similar line is **absorbed** into the neighbour: its own `raw_syntax` is
  discarded and the neighbour's `semantic_meaning` is overwritten (`:163-173`).
  `update()` unconditionally sets `admin_confirmed=True, confidence=1.0` (`:239-241`) and
  appends a **pre-change** version record (`:216-229`). There is no `reject` method and
  no list limit (`:250-266`); `get_stats()` orders a `set()` (`:277`).
- **Repository lookup**: `vendor.ilike` + `platform.ilike` + `raw_syntax ==
  raw_syntax.strip()` with `scalar_one_or_none` (`repositories/knowledge_base.py:44-55`).
  The module's own `fuzzy_lookup` (`:57-94`) has **no caller** anywhere in `app/`.
  `create()` writes no version record (`:114-144`); `update()` appends a **pre-change**
  record built before the field assignment (`:169-179`) and then forces
  `admin_confirmed=True, confidence=1.0` (`:189-191`); `list_mappings` defaults to
  `limit=100` with no total (`:213`); `get_stats` uses `func.distinct` with no ORDER BY
  (`:259-279`).
- **REST surface**: POST rejects an **exact, case-sensitive** duplicate with 409
  (`training.py:81-94`) and forces `admin_confirmed=True, confidence=1.0` (`:103-104`),
  then writes the initial v1 record (`:115-125`). PUT increments `version`
  unconditionally (`:165-171`) with a post-change record - the API convention is the
  opposite of both storage layers. Confirm/reject are audit-logged
  (`:374-383`, `:445-454`); REJECT writes **no** version record. List params are
  `vendor/platform/confirmed/page/per_page` - no confidence. All 8 endpoints depend on
  `get_current_user` only; `require_admin`/`require_auditor` exist in
  `auth.py:145-146` and are used by sibling routers, but not here.
- **Adaptive layer**: `reject_mapping` deletes a row **only if it is unconfirmed**
  (`adaptive.py:198-223`, confirmed row -> returns `False`, nothing changes);
  `reanalyze_with_mapping` hardcodes `CiscoIOSParser` (`:240-243`).
- **Storage**: `semantic_mappings` has no UNIQUE constraint, `universal_model_path` is
  nullable, `confidence` is `FLOAT`, `created_by_id` is `UUID NOT NULL` with an FK to
  `users`; `mapping_versions.changed_by_id` is `NOT NULL`. `raw_syntax` is unindexed.
- **Nothing consumes it.** `normalization.py` and `semantic.py` have no knowledge-base
  import (verified by import and body grep); `AdaptiveLearningEngine` is referenced only
  by `tests/test_ai_integration.py`. The only modules importing the knowledge base are
  its own definition, the repository, `training.py`, `adaptive.py` and the API package.

## 4. Results by category

| Cat | Scope | Rows | PASS | FAIL | Headline |
|---|---|---|---|---|---|
| A | Spec schema / structure (§15.1, §12) | 8 | 3 | 5 | no UNIQUE constraint; nullable model path; FLOAT/UUID instead of DECIMAL/VARCHAR; `created_by` missing from the API response |
| B | In-memory `KnowledgeBase` contract | 17 | 12 | 5 | fuzzy absorption loses the stored syntax and meaning; edit confirms; no version at create; REJECT is a no-op on confirmed rows |
| C | `KnowledgeBaseRepository` contract | 13 | 6 | 7 | exact-only lookup, dead `fuzzy_lookup`, pre-change+auto-confirm updates, `IntegrityError` on missing actor, list truncated at 100 |
| D | REST API contract (`training.py`) | 18 | 10 | 8 | case-mismatch duplicates crash lookup; no admin role; unvalidated model path/syntax; phantom version on no-op PUT; unversioned REJECT |
| E | Workflow contract (§9.2, §14.3, §15.3) | 10 | 4 | 6 | §9.2 step 5 absent; §15.3 quality scoring absent; confidence never stored, filtered or routed |
| F | Drift: in-memory vs repository vs API | 8 | 0 | 8 | every implementation answers lookup/version/reject/confirm/duplicate/list differently; two unrelated `TrainingMapping` classes |
| G | SEPARATE RECORD - wrong-vendor consequences | 7 | 4 | 3 | isolation itself holds; but vendor filters are case-inconsistent, `%` is a live pattern, multi-row matches crash |
| H | Semantic fidelity of stored meanings | 3 | 1 | 2 | empty `semantic_meaning` accepted; model path never validated at any entry point |
| I | Pipeline integration (§9.2 / §10.6 duties) | 6 | 1 | 5 | normalization and semantic analysis never consult the KB; adaptive engine unreachable; hardcoded Cisco parser |
| J | Determinism | 3 | 2 | 1 | state is reproducible; stats/list **order** is not |
| K | Performance (measurement only) | 3 | 2 | 1 | lookups fast; `create()` is quadratic (14.1x time for 4x input) |
| L | Hostile / boundary input | 9 | 2 | 7 | NUL reaches the driver (HTTP 500); 1 MiB syntax accepted; negative limit and 51-char vendor are raw DB errors |
| | **Total** | **105** | **47** | **58** | 47 CONFIRMED BEHAVIOR, 18 BUG, 18 DESIGN LIMITATION, 16 MISSING, 6 RECOMMENDATION |

## 5. Expectations (and where they come from)

No external "industry standard" is invoked. The expectations are:

1. **The project's own specification** (§10.6, §9.2, §14.1, §14.3, §15.1, §15.2, §15.3)
   - a written contract this code claims to implement (`training.py` docstring: "Training
     endpoints - mapping lifecycle per SPEC section 15"; `knowledge_base.py:1-16`
     describes the §9.2 loop).
2. **The project's own schema**: the `semantic_mappings` DDL and migration 001 are checked
   against the §15.1 column list literally (constraint, nullability, type, bound).
3. **Internal consistency**: three implementations of one logical contract must answer
   identically, otherwise "the knowledge base says X" is undefined. CONFIRM/EDIT/REJECT
   are defined in §9.2 step 3 as distinct administrative actions, so a write that also
   confirms has collapsed two of them.
4. **Self-declared behaviour**: docstrings and comments are checked against the code -
   e.g. the repository's `fuzzy_lookup` docstring promises "Fuzzy match for similar
   syntax" but no production call site exists; the in-memory `update()` docstring
   promises to "Update and version" while it also confirms.
5. **Consequences, not just clauses**: a defect counts only when it changes an observable
   outcome - a crash, a wrong mapping served, an unreachable row, an unauthorized write.

## 6. Hypotheses (26 CONFIRMED, 4 REJECTED, 0 unverifiable)

**CONFIRMED**

- **H06-01** the §15.1 `UNIQUE(vendor, platform, raw_syntax, version)` constraint is
  absent, so duplicate rows can be written and lookup then crashes with
  `MultipleResultsFound` (V06-01/31/41).
- **H06-02** the stored schema drifts from §15.1 and the §12 interface: nullable
  `universal_model_path`, `FLOAT` confidence, `UUID created_by`, and the API response
  omits `created_by` (V06-02/06/07/08).
- **H06-03** the in-memory store absorbs a distinct but similar syntax into a neighbour,
  losing the new `raw_syntax` and serving a different command's meaning
  (V06-15/16; 216 corpus lines, section 7).
- **H06-04** editing a mapping **confirms** it in the storage layers - CONFIRM / EDIT /
  REJECT are not distinct (V06-17/34/71).
- **H06-05** a mapping is not versioned from creation in two of three paths; only later
  changes produce a record (V06-18/68).
- **H06-06** REJECT is broken or absent for confirmed mappings: the adaptive workflow
  silently no-ops where the API unconfirms the row (V06-24/70).
- **H06-07** missing actor ids surface as a raw DB `IntegrityError` instead of a typed
  API error (V06-27).
- **H06-08** a mapping stored with trailing whitespace in `raw_syntax` is permanently
  unreachable - write does not strip, read compares only the stripped query (V06-30).
- **H06-09** lookup behaviour is implementation-specific: the repository's `fuzzy_lookup`
  is never called, and the repository matches exactly where the in-memory twin
  fuzzy-matches above 0.8 (V06-32/33/67).
- **H06-10** unfiltered lists silently truncate: API page = 100, repository default
  `limit=100` with no total, in-memory returns everything (V06-36/73).
- **H06-11** duplicate detection and listing use case-sensitive vendor equality while
  lookup uses `ilike`, so case-variant duplicates are accepted and later crash lookup
  (V06-41/53).
- **H06-12** training endpoints never require an administrator although §10.6 and §14.1
  reserve them, and sibling routers already use `require_admin`/`require_auditor`
  (V06-52).
- **H06-13** mapping content is not validated at the API boundary: bogus
  `universal_model_path`, empty `raw_syntax`, empty `semantic_meaning` all accepted
  (V06-42/43/82/83).
- **H06-14** version history records the wrong things: a no-op PUT writes a phantom
  version, a REJECT writes none (V06-45/50).
- **H06-15** a KB-served hypothesis reports a constant security relevance of `medium`
  instead of the mapping's own assessment (V06-56).
- **H06-16** §9.2 step 5 is not implemented: confirming a mapping never re-runs
  normalization or compliance, and nothing downstream reads the knowledge base
  (V06-59/60).
- **H06-17** §15.3 mapping quality scoring is not implemented (V06-62).
- **H06-18** AI confidence is computed but never stored, updated, filtered or acted on;
  no review routing for low confidence (V06-63/64/65/89).
- **H06-19** the three implementations drift on version content, on what a create
  records, and on duplicate handling (V06-68/69/72).
- **H06-20** two unrelated classes are both called `TrainingMapping` and are not
  interchangeable (V06-74).
- **H06-22** case-variant vendor strings and SQL wildcards change lookup results -
  `%` answers for any vendor, and a multi-row match crashes with
  `MultipleResultsFound` (V06-78/79/80).
- **H06-23** the knowledge base is not wired into the product: normalization and the
  semantic analyzer never consult it, and the adaptive engine is only reachable from
  tests (V06-85/86/88).
- **H06-24** re-analysing after an edit always uses the Cisco IOS parser regardless of
  the mapping's vendor (V06-87).
- **H06-25** stats/list output order is not deterministic - `list(set(...))` in memory,
  `func.distinct` without ORDER BY in SQL (V06-92).
- **H06-27** `KnowledgeBase.create` scales quadratically with store size (V06-94;
  5,000 creates = 16.7 s).
- **H06-28** hostile or degenerate input reaches the database or crashes the caller: NUL
  bytes, 1 MiB syntax, non-string syntax, negative limit, over-length vendor, wildcard
  list filters (V06-97/98/99/101/102/103/105).

**REJECTED**

- **H06-21** "mappings leak across vendors" - rejected: exact hit for the right vendor,
  miss for other vendors and platform variants in all three implementations, plus 408
  cross-vendor corpus queries with 0 breaches (V06-75/76/77/81).
- **H06-26** "identical operation sequences produce different knowledge-base state" -
  rejected: state is reproducible in memory and over Postgres (V06-91/93). Only
  *ordering* of stats output varies (H06-25).
- **H06-29** "SQL injection through lookup can extract or destroy data" - rejected:
  parameterized statements; payloads return no row and destroy nothing (V06-100).
- **H06-30** "the §14.3.5 offline fallback does not work" - rejected: a hypothesis is
  served from a confirmed KB mapping without contacting an LLM, both through
  `/training/hypothesis` and the workflow layer (V06-55/90).

## 7. Dataset sweep (480 real files, 479 ingested)

`scripts/engine_validation/sweep_knowledge_base.py`, caps: 120 lines / 200 chars per
file (KBs of at most ~120 rows per file, so absorption is measured per file rather than
against one giant store). 1 file (`fork-config.cfg`) contained 0 eligible lines.

### 7.1 Pass 1 - per-file ingestion and lookup

| Measure | Value |
|---|---|
| Files ingested | 479 (of 480 seen) |
| Lines loaded | 31,952 |
| Absorbed into a different row | 216 (**0 exact, 216 fuzzy**) = 0.68% of lines |
| Lookup after ingestion | 31,736 exact hits, **216 collisions**, 0 misses |
| Load time | 4,679.8 ms sum, 37.4 ms max per file, 0.31 ms max per create |
| Sweep elapsed | 5.48 s (3 passes) |

Every absorbed line is also a **collision**: the line's own syntax was discarded, so a
later lookup of that literal line returns a *different* stored syntax and a different
meaning. Absorption by label: juniper 66/3,319 (2.0%), paloalto 41/4,135 (1.0%),
fortinet 19/2,061 (0.9%), cisco 85/16,798 (0.5%), arista 1, frr 4; a10/f5/napalm 0.

Worst files: `Juniper\Firewalls\SRX\juniper_firewall` **26 of 46 lines (56.5%)**,
`Juniper\Switches\QFX\juniper_vlan` 2/10 (20%), `Cisco\MultiAS-Lab\mpls\
infrastructure\bgp-config.j2` and `Cisco\Routers\MPLS\bgp-config.j2` 8/50 each (16%),
`Juniper\Firewalls\SRX\configs_junos-srx-1.cfg` 15/115 (13%), `juniper_syslog` 11/92
(12%). These are template files whose repeated near-identical lines collapse into a
single row - the KB then answers for all 46 lines with one row's meaning.

### 7.2 Pass 2 - cross-file, same vendor (does one file's KB answer for another?)

| Pair (A -> B, same label) | Exact | Fuzzy collision | Miss |
|---|---|---|---|
| `drift-snapshot\as2border1.cfg -> example-bgp\as2border1.cfg` (cisco) | 120/120 | 0 | 0 |
| `MX-Series\atla.conf -> chic.conf` (juniper) | 82/120 | 0 | 38 |
| `4D-NGFW... -> 4D-Switching_LAN_Edge` (fortinet) | 14/120 | 0 | 106 |

No fuzzy wrong-meaning hits across files (the in-memory fuzzy path only fires above 0.8;
real cross-file duplicates are usually exact). Note the direction: B's lines are either
served exactly (they repeat A verbatim) or missed - **never answered with a different
file's meaning**. This is the strongest positive result of the sweep.

### 7.3 Pass 3 - cross-vendor isolation (SEPARATE RECORD, category G)

136 rows stored (cisco/juniper/fortinet/paloalto, 60 lines each from the largest file of
each label), each queried under the **other three** vendor labels: **408 queries, 0
breaches**, 18.7 ms. Isolation holds exactly (H06-21 rejected); the category G defects
are the case-sensitivity and `%`-pattern behaviours recorded in V06-78/79/80, which are
about *filter interpretation*, not about crossing vendor rows.

## 8. Performance (measurement only - not a readiness score)

| Measurement | Result |
|---|---|
| Corpus ingestion (479 files, <=120 rows each) | p50 0.102 ms, p95 0.211 ms, max 0.311 ms per create |
| In-memory lookups on a 1,000-row KB | 77 ms for 1,000 (probe) / 87 ms (test) = 0.08-0.09 ms each |
| Repository lookups (200 queries, indexed table) | 164 ms total = 0.8 ms each (only `ix_semantic_mappings_vendor_platform`; `raw_syntax` unindexed) |
| `KnowledgeBase.create` scaling | 200 creates = 22 ms; 800 = 309 ms (**14.1x for 4x input**); 5,000 = 16.7 s -> O(n^2) dedupe scan (`knowledge_base.py:163-180` compares every existing row) |
| Cross-vendor isolation sweep (408 lookups) | 18.7 ms |

Reads are comfortably interactive. Writes are the problem: a store of 5,000 mappings
takes ~17 seconds to build and grows quadratically.

## 9. Findings

### Blocking (must be fixed before this engine is ready)

**F1 - The section 10.6 duty is unwired: nothing that normalizes or analyzes consults
the knowledge base (H06-23, H06-16).**
- §10.6 opens with "Provide lookup for normalization"; `app/engines/normalization.py`
  and `app/ai/semantic.py` have no knowledge-base import in either their import blocks
  or their bodies (V06-85/86).
- §9.2 step 5 ("re-run normalization and compliance evaluation with the new mapping")
  has no implementation: no engine or compliance module references the KB
  (V06-59/60), so confirming a mapping changes nothing downstream.
- The adaptive learning engine - the component that would actually apply a mapping to a
  re-analysis - has no caller outside `tests/test_ai_integration.py` (V06-88).
- Upstream context (Engine 05, V05-85 "training has no effect on normalization") is
  thereby confirmed **from this engine's side too**: the wiring is missing on both ends.
  This engine asserts only its own evidence.
- Net: the knowledge base is a well-populated table nothing reads. Every other finding
  below is about a store whose output has no consumer.

**F2 - One logical contract, three divergent implementations (H06-09, H06-10, H06-19,
H06-20, and the category F family).**
- Lookup: in-memory fuzzy >0.8 (`knowledge_base.py:120-131`) vs repository exact-only
  (`repositories/knowledge_base.py:44-55`) - same query, `True` vs `False`
  (V06-33/67). The repository even ships a `fuzzy_lookup` nobody calls (V06-32).
- Edit: API PUT leaves `admin_confirmed=False`; repository and in-memory `update()` both
  force `True, confidence 1.0` (V06-71) - three answers to "what does editing do".
- Version content: API records post-change values, both storage layers record
  **pre-change** values (built before the field assignment at `repositories:169-179`,
  `knowledge_base.py:216-229`) - so "version 2 means X" is convention-dependent
  (V06-69).
- Create: API writes an initial record, both storage layers write none (V06-68).
- Duplicate handling: API 409 on exact duplicates, in-memory silently overwrites the
  meaning, and near-duplicates are absorbed by one and accepted by the other
  (V06-72).
- List: API pages at 100 (with `meta.total`), repository truncates at 100 with no
  total, in-memory returns all (V06-36/73); list filters honour `%` in the repository
  but not in memory (V06-105).
- Reject: API unconfirms + annotates, adaptive deletes only unconfirmed rows, neither
  storage layer has a reject at all (V06-70).
- Two unrelated classes share the name `TrainingMapping` and are not interchangeable
  (V06-74).

**F3 - Editing confirms the mapping: the administrator gate is bypassed by any write
(H06-04).**
- In-memory `update()` sets `admin_confirmed=True, confidence 1.0` unconditionally
  (`knowledge_base.py:239-241`); probe: `(False, 0.5, 1) -> (True, 1.0, 2)` from adding
  an admin note (V06-17).
- Repository `update()` does the same (`repositories/knowledge_base.py:189-191`)
  (V06-34).
- §9.2 step 3 defines CONFIRM, EDIT and REJECT as three distinct actions and §14.3.3
  requires human approval; an edit that also confirms means an unreviewed mapping can
  reach `admin_confirmed=True, confidence=1.0` through a side door. The API PUT layer
  behaves correctly (V06-47) - the defect is in both storage layers underneath it.

**F4 - Lookup is not total: duplicates and wildcards crash it with HTTP 500 (H06-01,
H06-11, H06-22).**
- No `UNIQUE(vendor, platform, raw_syntax, version)` in the model, in migration 001, or
  anywhere else (V06-01; §15.1 requires it).
- The API's duplicate check compares vendor with `==` (case-sensitive,
  `training.py:82`) while lookup uses `ilike` (case-insensitive,
  `repositories:45`): POST `cisco` then `Cisco` with the same syntax creates **two**
  rows, and the next lookup raises `MultipleResultsFound` -> unhandled -> HTTP 500
  (V06-41; probe reproduces it).
- The same crash is reachable without duplicates: `lookup('%', '%', 'show version')`
  matches every vendor through `ilike` with no ESCAPE clause (V06-79/80).
- `GET /training/mappings?vendor=cisco` cannot see a row stored as `Cisco` - the list
  filter is `==` while lookup is `ilike` (V06-53), so the admin UI can miss the very
  rows that break lookup.

**F5 - Fuzzy absorption corrupts the knowledge it stores (H06-03).**
- `create()` of a distinct-but-similar line (Jaccard 0.875) stores **one** row: the
  neighbour's `raw_syntax`, the new line's meaning - the new syntax is gone
  (V06-15).
- `lookup()` of a line at similarity 0.833 returns a **different command's** mapping and
  meaning (V06-16).
- On the real corpus this is not theoretical: 216 of 31,952 lines (0.68%) were absorbed
  into a different row, worst file 56.5% (`Juniper\Firewalls\SRX\juniper_firewall`, 26
  of 46 lines), and each one subsequently answers with another line's meaning
  (section 7.1). Because F1 means no consumer exists yet, this defect is latent rather
  than currently user-visible - it becomes live the moment normalization starts reading
  the KB.

**F6 - Training endpoints have no authorization beyond "is logged in" (H06-12).**
- All 8 endpoints in `training.py` (`:31, 76, 134, 152, 196, 237, 341, 414`) depend on
  `get_current_user` only; there is no `require_admin`, `require_role` or equivalent
  (V06-52).
- §10.6 assigns updates to the administrator, §14.1 says the administrator
  confirms/rejects, §15.2 step 3c assumes an admin decision; the codebase already has
  `require_admin`/`require_auditor` (`auth.py:145-146`) and sibling routers
  (`configurations.py:72,219`) use them. Any authenticated user can therefore create,
  edit, **confirm** and reject mappings - which, combined with F3, means any user can
  push a mapping to `admin_confirmed=True, confidence=1.0`.

### Secondary findings

- **F7** version history is not a trustworthy audit record: no record at creation in two
  of three paths (V06-18/68); a no-op PUT writes version 2 with `reason=None`
  (V06-45); REJECT writes nothing (V06-50); the two storage layers snapshot
  pre-change values while the API snapshots post-change (V06-69); a missing actor id
  surfaces as `IntegrityError` from flush (`changed_by_id NOT NULL`) instead of a typed
  4xx (V06-27).
- **F8** schema drift from §15.1/§12: `universal_model_path` nullable (spec NOT NULL)
  (V06-02), `confidence` FLOAT vs DECIMAL(5,2) (V06-06), `created_by_id` UUID vs
  VARCHAR(100) (V06-07), and the API response omits `created_by` entirely, so the §12
  interface is not exposed (V06-08).
- **F9** content is unvalidated at every entry point: a `universal_model_path` that does
  not exist in the Universal Security Model is stored (V06-42/83 - cross-ref Engine 05,
  where the AI path validator is prefix-based), empty `raw_syntax` is accepted (V06-43),
  empty `semantic_meaning` is accepted (V06-82), and there is no size bound on
  `raw_syntax` while `semantic_meaning` is capped at 500 (V06-99).
- **F10** confidence is dead data: POST hardcodes `confidence=1.0` and the
  Create/Update schemas have no confidence field (V06-63), so an AI hypothesis's
  estimated confidence (§14.1) cannot be stored; nothing recomputes it (V06-64); the
  list endpoint has no confidence filter (V06-65); and no code routes low confidence to
  REVIEW (§14.3.2) - the only threshold in the codebase is
  `compliance/evidence.py:169`, a different signal (V06-89).
- **F11** §15.3 quality scoring (admin confirmations, consistency, age/version history,
  AI confidence at creation) is absent: no `quality_score`/`mapping_quality` anywhere;
  `get_stats` only counts rows (V06-62) - and two of the four axes' raw ingredients
  (confirmation counts, confidence history) are themselves unrecorded (V06-63/F10).
- **F12** an orphan row: a `raw_syntax` stored with trailing whitespace (the API stores
  verbatim, `training.py:97-108`) is unreachable by either the plain or the spaced
  query, because read compares `raw_syntax == query.strip()` (V06-30).
- **F13** filter interpretation is inconsistent everywhere: vendor case-sensitive for
  dedup and list, case-insensitive for lookup (V06-53/78); `%`/`_` honoured by
  repository `ilike` filters (lookup and list) but literal in memory (V06-79/105).
- **F14** report-relevant output is not stably ordered: 3 of 3 subprocess runs of
  `get_stats` returned a different vendor order (`list(set(...))` in memory,
  `func.distinct` with no ORDER BY in SQL) (V06-92).
- **F15** hard-coded shortcuts: a KB-served hypothesis reports security relevance
  `medium` regardless of the mapping (V06-56), and
  `adaptive.reanalyze_with_mapping` always instantiates `CiscoIOSParser` (V06-87) - a
  Juniper or Fortinet mapping re-analysis would be parsed as IOS.
- **F16** `KnowledgeBase.create` is O(n^2) over the store: 14.1x time for 4x input,
  5,000 rows in 16.7 s (V06-94). Reads are fine (F-perf table, section 8).
- **F17** hostile input is not neutralised before the driver: NUL bytes are stored in
  memory and, over the repository, surface as an unhandled
  `asyncpg.exceptions.InvalidTextRepresentation` -> HTTP 500 rather than a typed error
  (V06-97/98, CWE-158 class); `limit=-1` and a 51-char vendor likewise reach Postgres
  and raise raw `DBAPIError` from the repository, which is a public API even though the
  HTTP layer guards it with `Query(ge=1)`/`max_length` (V06-101/102); a non-string
  `raw_syntax` raises `AttributeError: 'int' object has no attribute 'lower'` from
  `create()` (V06-103).

### What works

- **Vendor/platform isolation** (category G positive): exact hit for the right vendor,
  miss for other vendors and platform variants in all three implementations, unknown
  vendors accepted (§10.6 is a learning store), and **408 cross-vendor corpus queries
  with 0 breaches** (V06-75/76/77/81; H06-21 rejected).
- **Lookup basics**: hit returns the stored mapping, miss returns `None`, vendor/platform
  matching is case-insensitive and whitespace-tolerant as the docstring promises
  (V06-09/10/11), repository identical for exact hits (V06-28/29).
- **REST lifecycle**: POST stores version 1, `admin_confirmed=True`, confidence 1.0 with
  an initial "Initial creation" record (V06-39); exact duplicate -> 409 keeping the
  original (V06-40); PUT does **not** confirm (V06-47) and records the change with a
  reason (V06-46); confirm sets confirmed/confidence/version + record + audit row
  (V06-48); reject unconfirms with a `REJECTED:` note and is audit-logged
  (V06-49/51); clients cannot set trust fields (V06-54); vendor > VARCHAR(50) rejected
  at the schema boundary (V06-44); all §9.2 steps have a code path (V06-66).
- **Offline fallback (§14.3.5)**: `/training/hypothesis` serves a confirmed KB mapping
  without contacting an LLM (V06-55/90; H06-30 rejected) - the AI-safety audit trail
  for both AI-success and AI-failure paths exists (V06-61).
- **Storage mechanics**: `create()` persists every field (V06-26); spec §15.1 NOT NULL
  columns hold, `admin_confirmed` defaults false, `version` defaults 1 (V06-03/04/05);
  typed errors for unknown ids (V06-20/21); list/count/stats filters work and stats
  match across implementations (V06-22/23/37/38); `update()` appends exactly one record
  (V06-19/35); identical re-create does not duplicate a row (V06-14); an absorbed
  create still leaves a *consistent* record - content, authorship and version history
  all reflect the surviving row (V06-84).
- **Determinism of state**: identical operation sequences yield identical KB state in
  memory and over Postgres (V06-91/93; H06-26 rejected) - only stats *ordering* varies
  (F14).
- **Read performance**: 0.09 ms/in-memory lookup, 0.8 ms/repository lookup on the
  indexed table (V06-95/96), 0.1-0.3 ms per corpus create.
- **Input security at the HTTP layer**: SQL injection payloads through lookup cannot
  extract or destroy data - parameterized statements (V06-100; H06-29 rejected); list
  filters match literally at the HTTP boundary (V06-104).

## 10. Cross-engine baseline (E01-E05 artifacts, read-only)

- Engine 01 (PARTIAL) / 02 (FAIL) / 03 (FAIL) / 04 (FAIL): none of them consumes the
  knowledge base; nothing gates its creation or confirmation.
- Engine 05 (FAIL) carried as **upstream context only** per the user's directive: its
  V05-85 ("training has no effect on normalization") is the same wiring gap this engine
  measures from the KB side (V06-85); its §10.5 finding and this engine's F1 are two
  halves of one missing link (normalization has no KB import; the KB has no normalization
  caller). No Engine 05 defect is claimed as fixed, and none is re-tested here.
- Full suite before E06: 845 collected / 819 passed / 26 failed -> after:
  **950 / 924 / the same 26 pre-existing failures** (105 new tests). The failure set is
  unchanged in composition: 6 `test_benchmark_execution.py`, 2 `test_detection.py`, 2
  `test_frontend_integration_support.py`, 7 `test_juniper_benchmark.py`,
  2 `test_phase5_integration.py`, 6 `test_phase8_hardening.py`, 1
  `test_vertical_slice.py::test_cisco_ios_full_pipeline`.
- `git diff -- backend/app/` **empty**; `git status --porcelain -- backend/app/`
  **empty**. Working tree matches the recorded pre-existing baseline (requirements.txt,
  frontend package files, plus the untracked validation/artifacts/scripts directories).
- New files only: `tests/validation/test_v06_knowledge_base.py`,
  `scripts/engine_validation/{sweep,report}_knowledge_base.py`,
  `artifacts/engine_validation/06_knowledge_base/*`, plus the conftest engine mapping for
  `06_knowledge_base`.

## 11. NOT APPLICABLE / NOT VERIFIABLE

- **ML model quality** - deferred by instruction (engines validated before ML).
- **Effect of a confirmed mapping on live compliance outcomes** - F1 means there is no
  live consumer yet; §9.2 step 5 behaviour is recorded as MISSING (V06-59/60) rather
  than measured end-to-end. Engines 07/11 own downstream evaluation.
- **Quality-axis scoring correctness (§15.3)** - not implemented at all (V06-62); there
  is no scoring to evaluate.
- **Concurrency, locking and transactional behaviour** - all probes are single-threaded;
  no concurrent writer/reader interleavings were tested.
- **Authentication/authorization penetration testing** - F6 is established from the
  route source (dependencies used vs available); no live session/token abuse testing was
  performed, and no dependency CVE scan was run.
- **Whether the 0.8 similarity threshold is the "right" threshold** - no ground truth for
  it exists in this repository; the sweep measures the threshold's consequences (216
  absorptions), not its optimality.
- **Postgres performance beyond the measured index** - `raw_syntax` is unindexed; only
  200 lookups on the existing composite index were measured.

## Limitations of this validation

- Sweep caps (120 lines, 200 chars per file) keep each pass-1 KB at <=120 rows, so
  absorption rates are per-file; the O(n^2) write cost is measured separately by the
  5,000-row probe. A single store holding all 31,952 lines would show a much larger
  collision count (every distinct near-duplicate pair in the corpus, not just
  within-file ones) and quadratic build time - not attempted for runtime reasons.
- "Absorbed" means `create()` did not store the line's own `raw_syntax` (the KB's own
  dedupe decided the line was a duplicate). No human ground truth for which corpus lines
  are truly duplicates was available; pass 2's exact-match result is the closest proxy.
- Category G uses directory labels only to choose content for wrong-vendor probes; no
  detection accuracy is claimed.
- In-memory and repository comparisons run in one process against one throwaway
  database (`engine_validation_test`); results reflect this SQLAlchemy/asyncpg version
  only.
- Performance numbers are single-machine measurements, not a readiness score.
- Hypothesis conclusions are derived only from the recorded evidence rows; no claim goes
  beyond them.

---

## 12. Verdict

**FAIL - NOT READY.** Six blocking findings:

| | Finding | Evidence |
|---|---|---|
| F1 | §10.6 duty unwired - normalization/semantic never read the KB, §9.2 step 5 absent, adaptive engine unreachable | V06-59/60/85/86/88, H06-16/23 |
| F2 | One contract, three divergent implementations (lookup, versions, reject, confirm, duplicates, list) | V06-32/33/36/67..74, H06-09/10/19/20 |
| F3 | Editing confirms the mapping - the §9.2/§14.3.3 administrator gate is bypassed | V06-17/34/71, H06-04 |
| F4 | Lookup is not total - case-duplicate rows and `%` wildcards crash it with HTTP 500 | V06-01/31/41/53/79/80, H06-01/11/22 |
| F5 | Fuzzy absorption stores the wrong syntax/meaning - 216 corpus lines affected, worst file 56.5% | V06-15/16 + sweep 7.1, H06-03 |
| F6 | Training endpoints have no administrator requirement - any authenticated user can confirm mappings | V06-52, H06-12 |

Secondary: F7-F17 (untrustworthy version history, schema drift, unvalidated content,
dead confidence signal, absent quality scoring, orphan rows, filter inconsistency,
unstable ordering, hardcoded parser/relevance, quadratic writes, NUL and unguarded
inputs reaching the driver).

What is solid: vendor/platform isolation (including 408 cross-vendor corpus queries with
0 breaches), the REST lifecycle's confirm/edit/reject semantics *as exposed*, offline KB
fallback, deterministic state, fast reads, and parameterized queries. The blocking
problems are integration (nothing reads it), contract convergence (three disagreeing
implementations), the administrator gate, lookup totality and authorization - not
robustness of reads or speed.
