# ENGINE 01 — Configuration Ingestion: Fix & Hardening Report

Report date: 2026-09-26. Engine: `01_configuration_ingestion`.
Code: `backend/app/engines/ingestion.py` (single source of truth) and the minimal
integration files required by the fix prompt. Validation evidence:
`backend/artifacts/engine_validation/01_ingestion/` (pre-fix snapshot preserved in
`01_ingestion_pre_fix/`).

---

## 1. Scope and identification

Findings covered: **F1–F11** (from `01_ingestion_pre_fix/ENGINE_REPORT.md`) and
**N1–N10** (gap/negative findings from the fix prompt). Files changed by this work:

| File | Role |
|---|---|
| `app/engines/ingestion.py` | Core rewrite — contract, validation, decode, duplicates, typed errors |
| `app/api/v1/configurations.py` | Upload route delegates to the engine; bounded read; error mapping |
| `app/main.py` | ASGI middleware rejecting oversized upload bodies before parsing |
| `app/models/__init__.py` | `uq_configurations_content_hash` unique index |
| `app/config.py` | `.zip` removed from `ALLOWED_EXTENSIONS` |
| `alembic/versions/004_unique_content_hash.py` | Migration: dedupe + drop `ix_` + create unique index |
| `requirements.txt` | Version pins aligned to the installed environment; no package added or removed |
| `tests/validation/test_v01_ingestion.py` | V01-41 … V01-65 regression block added (98 tests total) |
| `tests/validation/test_v02_validation.py` | V02-33 expectation updated to the fixed contract (see §11) |

Out of scope and untouched: Engines 02–12, auth/rate-limit/CORS/security headers,
AI/queues/Redis, the frontend (its pre-existing uncommitted changes were left alone).

## 2. Status vocabulary

Statuses used in §3–§4, exactly as required: **FIXED**, **NOT FIXED**,
**NOT APPLICABLE**, **DESIGN DECISION**. No numeric scores or readiness grades are
assigned anywhere in this report; counts, latencies and pass/fail tallies are
measurements, not scores.

## 3. Findings F1–F11 — status

| ID | Finding (pre-fix) | Status | What was done | Evidence |
|---|---|---|---|---|
| F1 | `FileDecodeError` unreachable; `latin-1` fallback accepted every byte, binary silently became text | **FIXED** | Strict UTF-8 → strict cp-1252 → `FileDecodeError` (reachable); decode happens only after NUL/signature/density gates | V01-47, V01-24 (FAIL→PASS), V01-64; `ingestion.py:542` |
| F2 | Filename >255 escaped as untyped `DBAPIError` (column `String(255)`) | **FIXED** | `MAX_FILENAME_LENGTH = 255` enforced in-engine; 256+/empty/non-str rejected typed | V01-30 (FAIL→PASS), V01-19, V01-41 |
| F3 | NUL bytes in content failed at PostgreSQL as `CharacterNotInRepertoireError`, escaping `ingest()` untyped | **FIXED** | NUL and control characters rejected before any DB work, typed | V01-40 (FAIL→PASS), V01-45 |
| F4 | No binary/magic-byte check at ingestion; `BINARY_CONTENT` ran much later | **FIXED** | Same rule as `ConfigurationValidator._has_binary_content`: 12 known signatures + non-printable density heuristic, before decode/persist | V01-34 (FAIL→PASS), V01-46 |
| F5 | `.zip` allow-listed but never extracted; size checked on compressed bytes | **FIXED** | `.zip` removed from `settings.ALLOWED_EXTENSIONS`; archives rejected at the extension gate with a typed error (decision: no archive support, see §9) | V01-15 (PARTIAL→PASS), V01-16 (PARTIAL→PASS) |
| F6 | Traversal-shaped and NUL filenames accepted verbatim; never normalised | **FIXED** | Printable strings only; `/`, `\`, drive letters, control chars, ZWSP rejected; nothing traversable can persist | V01-17 ×7 (PARTIAL→PASS), V01-18, V01-35, V01-42, V01-61 |
| F7 | `content_type` an unvalidated caller string | **FIXED** | Syntax-validated (`type/subtype`, printable), length-bounded to the `String(50)` column, advisory only — extension and bytes stay authoritative | V01-20, V01-27, V01-43, V01-44 |
| F8 | Zero-byte configs accepted with `line_count=0`, no explicit contract | **FIXED** | Contract decided and encoded: empty/whitespace-only content rejected typed; comment-only content explicitly valid | V01-31, V01-49, V01-57 |
| F9 | Engine imported by nothing; upload path re-implemented ingestion with different semantics | **FIXED** | Route performs transport only (bounded read) and delegates every rule to `IngestionEngine`; no ingestion logic remains in the endpoint | V01-37 (FAIL→PASS), V01-58, V01-60; diff of `configurations.py` |
| F10 | `ingest()` returned only an id; audit hand-off was an unmediated DB read | **FIXED** | `IngestionResult` carries decoded content for same-request consumers; persisted row documented as cross-request source of truth | V01-38, V01-63, V01-50 |
| F11 | `ingest()` never flushes; durability depended on the caller | **FIXED** | Contract recorded: `ingest()` flushes, never commits; caller-owned transaction tested (flush visible / rollback discards / commit persists) | V01-26, V01-32, V01-56 |

No F finding remains NOT FIXED or NOT APPLICABLE.

## 4. Findings N1–N10 — status

| ID | Finding (pre-fix) | Status | What was done | Evidence |
|---|---|---|---|---|
| N1 | Duplicate pre-check over historical duplicate rows could raise untyped `MultipleResultsFound` | **FIXED** | Limited projection (`select(id).where(...).limit(1)`) returns a single winner UUID regardless of corrupted history | V01-53, `ingestion.py:458` |
| N2 | Missing/invalid `device_id` surfaced as untyped FK `DBAPIError` | **FIXED** | UUID shape validated; existence pre-checked; race-window FK violations translated to a typed error | V01-55, V01-62, `ingestion.py:473`, `:485` |
| N3 | Filename path/control-character safety not enforced before persistence | **FIXED** | `_validate_filename` (printable, no separators/drive letters/control chars, ≤255) runs before any DB work | V01-18, V01-42, V01-61 |
| N4 | `file_content` input type not contracted (non-bytes could flow through) | **FIXED** | Bytes contract enforced; `bytearray` accepted and normalised to `bytes`; anything else rejected typed | V01-48, V01-50 |
| N5 | Duplicate detection was application-level only; concurrent uploads could bypass it | **FIXED** | `uq_configurations_content_hash` UNIQUE index is the authoritative race guard; insert runs in `begin_nested()`; SQLSTATE 23505 translated to `DuplicateConfigurationError` carrying the winner id | V01-51, V01-52, V01-54, V01-60; migration 004 |
| N6 | Duplicate identity (what counts as "the same configuration") undefined | **DESIGN DECISION** | Byte-level identity retained deliberately: `content_hash = SHA-256(raw upload bytes)`; the pre-check is only a friendly fast path; logical-content identity would require normalisation semantics inside ingestion | `ingestion.py:32-36`, `:234`; V01-51/52/53 |
| N7 | `.zip` present in `ALLOWED_EXTENSIONS` (dual source: config + engine) while no extraction existed | **FIXED** | `.zip` removed from settings; engine reads the single allow-list; one contract, one source | V01-15, V01-16; `config.py` diff |
| N8 | Empty / whitespace-only content accepted as a configuration | **FIXED** | Rejected typed as meaningless before persistence; comment-only content remains valid | V01-31, V01-49, V01-57 |
| N9 | ZIP compressed-vs-expanded size (zip-bomb) handling | **NOT APPLICABLE** | No archive extraction path exists — `.zip` is rejected at the extension gate, so bomb semantics cannot arise. V01-16 records exactly this | V01-16 (`NOT APPLICABLE` evidence row) |
| N10 | Oversized uploads only checked after full read/parse; unbounded `await file.read()` | **FIXED** | Two layers: ASGI middleware 413 on declared content-length (upload path only, +64 KiB framing allowance), and route bounded read stopping at limit+1 MiB without materialising the body | V01-59, `main.py:49`, `configurations.py:94-108` |

## 5. Architecture — one ingestion source of truth (F9/F10/F11)

Before: `IngestionEngine` was dead code; `configurations.py` re-implemented hashing,
latin-1 decode, extension and duplicate logic with different semantics.

After: `upload_configuration` does exactly three transport things — require a
filename, bounded-read the part (`_UPLOAD_CHUNK_BYTES` = 1 MiB loop), and map typed
engine errors to HTTP statuses. Every rule (extension, size, filename safety, NUL/
binary gates, decode, content-type, duplicate identity, device association, flush)
lives in `ingestion.py`, documented in its module docstring. Duplicate handling at
the endpoint preserves the pre-fix idempotent API: identical content returns the
existing row (201); the defensive 409 branch only fires if the winner row cannot be
fetched. The engine flushes and never commits (F11) — `get_db` commits after the
handler, matching FastAPI stack semantics.

## 6. Error contract and exception hierarchy

`IngestionError` and eight subclasses, all raised before persistence for predictable
input problems: `FileTooLargeError`, `InvalidFileExtensionError`, `FileDecodeError`,
`DuplicateConfigurationError`, `InvalidFilenameError`, `InvalidContentError`,
`InvalidContentTypeError`, `InvalidDeviceError` (`ingestion.py:93-145`).

HTTP mapping in the route: `DuplicateConfigurationError` → existing row (201) /
fallback 409; `FileTooLargeError` → 413; any other `IngestionError` → 400 with the
typed message. Middleware 413 for declared oversize. Database internals are never
exposed: constraint races are translated to a generic typed message with the winner
id, not SQLSTATE text. The hostile-input battery (V01-64, 23 cases) asserts that no
raw `DBAPIError`/`IntegrityError`/`UnicodeDecodeError` escapes for invalid input.

## 7. Persistence, uniqueness and migration

- `Configuration.__table_args__` now carries `Index("uq_configurations_content_hash", "content_hash", unique=True)`; the old non-unique `ix_configurations_content_hash` is dropped by migration `004`, which first deletes rows beyond the lowest id per hash (dedupe), so it applies cleanly on databases containing historical duplicates.
- Race pattern: friendly pre-check → `begin_nested()` → INSERT → on SQLSTATE 23505 roll back the savepoint, re-read the winner, raise `DuplicateConfigurationError(configuration_id=...)`. Both same-session and two-session races verified (V01-51/52); the session remains usable afterwards.
- `content_type` stays an advisory string column (validated, `String(50)`-bounded) — see §9.

## 8. Endpoint and HTTP contract — register of behaviour changes

Each change below was deliberate, tested, and is a behaviour change relative to the pre-fix code:

1. **Decode**: `latin-1` (accepts every byte) → strict UTF-8 / strict cp-1252 / typed failure. Undecodable binary now 400 instead of persisted mojibake (F1; test V02-33 updated, §11).
2. **`.zip` uploads**: previously allow-listed (stored uncompressed as text) → now 400 `InvalidFileExtensionError`.
3. **Unsafe filenames**: traversal/NUL/control-char names previously stored verbatim → now 400 typed.
4. **Empty content**: previously accepted with `line_count=0` → now 400 typed.
5. **Oversized bodies**: previously read in full then rejected → rejected by middleware before multipart parsing, and by bounded read at limit+1 MiB (413 both layers).
6. **Nonexistent `device_id`**: previously untyped FK `DBAPIError` (500-class) → 400 typed.
7. **Filename >255 / bad `content_type`**: previously column-violation `DBAPIError` → 400 typed.
8. **Duplicate upload via endpoint**: idempotent success preserved (201 + existing row verbatim); detection itself now engine-owned and DB-enforced. Defensive 409 exists only when the winner row is unfetchable.
9. **Cross-file test update**: `tests/validation/test_v02_validation.py::test_v02_33` previously asserted that latin-1 keeps undecodable bytes; it now asserts `FileDecodeError` from `_decode_content`/`_validate_and_decode` while keeping its original `BINARY_CONTENT` validator assertion (status convention `PARTIAL` unchanged). This is the only test outside the E01 module changed by this work.
10. **Not changed**: response models, auth (`require_auditor`), rate limits, CORS, security headers, all other engines. Known pre-existing quirk left alone (out of scope): `device_id` is a query parameter on the route while the frontend form field of the same name is therefore ignored.

## 9. Design decisions

- **cp-1252 over latin-1 (F1)**: latin-1 maps all 256 byte values and can never fail, which is exactly why `FileDecodeError` was dead code. Strict UTF-8 first, strict cp-1252 fallback keeps real-world Cisco/Juniper ASCII/UTF-8 files working while making decode failure reachable.
- **Binary gates before decode (F4)**: 12 known file signatures plus the same non-printable density rule the validator uses (`_has_binary_text`, 10% threshold with comment/whitespace exemptions verified by the 10% vs 11% boundary test). The engine deliberately mirrors the validator rather than importing its private helper, so the two modules cannot drift silently; equivalence was probed on representative samples.
- **Bare `MZ` accepted, full binary signatures rejected**: `MZ` alone appears in text contexts; rejecting it would false-positive. Signature table + density heuristic together close the gap (V01-46).
- **ZIP exclusion (F5/N7/N9)**: one Configuration row per upload is the API contract; no safe bounded multi-member extraction path exists; the corpus contains no archives. Rejected at the extension gate rather than stored.
- **Byte-level duplicate identity (N6)**: logical-content identity would require defining normalisation inside ingestion (encoding, line endings, comments); byte identity is simple, deterministic, and already what the unique index enforces.
- **Flush-only (F11)**: retained deliberately; the caller owns the transaction and the FastAPI `get_db` commits after the handler.
- **Advisory `content_type` (F7)**: validated and stored for metadata, never authoritative — a `.cfg` claiming `application/zip` still ingests as text (V01-44 family).

## 10. Security checklist

| Control | Verified by |
|---|---|
| Path traversal cannot persist (`../..`, drive letters, backslashes) | V01-17 ×7, V01-42, V01-61 |
| Control characters / NUL / ZWSP rejected in filenames | V01-42, V01-61 |
| Oversize rejected pre-parse (middleware) + bounded read (route) | V01-59 (413 + 11-chunk stop, 0 rows) |
| Archives excluded from the allow-list | V01-15, V01-16 |
| Binary payloads rejected before any DB work | V01-46, V01-34 |
| NUL in content rejected pre-DB (no driver-level abort) | V01-45, V01-40 |
| Arbitrary bytes never silently converted to text | V01-47, V01-64 |
| `content_type` cannot influence storage decisions | V01-43, V01-44 |
| `device_id` must be a UUID of an existing device | V01-55, V01-62 |
| Duplicate race cannot bypass uniqueness (DB-enforced) | V01-51, V01-52, V01-54, V01-60 |
| Hostile input battery: all cases typed, no raw driver exceptions | V01-64 (23 cases) |
| Auth guard on upload unchanged (`require_auditor`) | diff review; V01-58 exercises authenticated path |
| No secrets/keys added; error details carry no SQL/stack traces | diff review; §6 translation tests |
| No new dependencies (requirements pins aligned only) | `requirements.txt` diff (§1) |
| Middleware registered before CORS so CORS stays outermost | `main.py:44` comment; V01-59 control request unaffected |

## 11. Test coverage

New block **V01-41 … V01-65** (25 tests) in `tests/validation/test_v01_ingestion.py`,
plus updated legacy rows; module now **98 tests**. Categories: A2, B4, C16, D27,
E12, F18, G4, H1, I5, J3, K6 (evidence rows). Finding → test mapping is recorded in
the `recommendation` field of each `raw_results.jsonl` row (e.g. `Fixed (E01 F3)`).
Shared fixture `_UploadClient` drives the real ASGI stack (overrides `get_db` /
`get_current_user`, cleanup in `__aexit__`) for K-category tests V01-58/60/61/62/63.

Evidence-row transitions pre-fix → post-fix (same ids, no test deleted):

- 5 **FAIL → PASS**: V01-24, V01-30, V01-34, V01-37, V01-40
- 13 **PARTIAL → PASS**: V01-15, V01-16, V01-17 ×5, V01-18, V01-19, V01-20, V01-31, V01-35, V01-38
- 27 new rows added (V01-41–V01-65 plus 2 extra V01-17 traversal variants)
- V01-39 remains NOT APPLICABLE (unsupported vendor syntax is out of ingestion scope)
- Total: 71 rows (52 PASS / 13 PARTIAL / 5 FAIL / 1 N/A) → **98 rows (97 PASS / 1 N/A)**

Cross-file update (disclosed per instructions): `test_v02_validation.py::test_v02_33`
now expects `FileDecodeError` from the engine's decode path (fixed F1 contract) and
keeps its original validator assertion — comment `# E01 FIX (F1):` in the test.

## 12. Regression results (final state, this session)

| Suite | Result |
|---|---|
| `tests/validation/test_v01_ingestion.py` (E01 module) | **98 passed**, 10.2 s |
| `tests/validation/` (all validation suites) | **822 passed**, 97 s |
| Full repository (`pytest`) | **1224 passed, 26 failed** (1250 collected), 108 s |

The 26 failures are pre-existing legacy tests (benchmark ×13, detection ×2,
frontend-integration ×2, phase5 ×2, phase8 ×6, vertical ×1). They were verified
**identical at clean HEAD (74ce952)** using a throwaway `git worktree` — the same 26
names fail there — and the worktree was removed. None is caused by this work.

## 13. Dataset re-validation (480 files)

Script: `scripts/engine_validation/sweep_ingestion_postfix.py` →
`dataset_results_postfix.csv` + `dataset_summary_postfix.json` (phase label
`post_fix (E01 F1-F11, N1-N10)`). Corpus: `C:\Users\priye\Downloads\SIH Config\final-dataset`,
480 files, 11.58 MB, originals untouched (verified by size/timestamp).

| Measure | Pre-fix | Post-fix |
|---|---|---|
| Accepted by pipeline | 337 | 337 |
| Rejected | 143 (extension) | 143 (`InvalidFileExtensionError`, only rejection type) |
| Would be accepted by full ingest | 256 | 256 |
| Fixture classes (Known-good / Unsupported / Edge / Duplicate) | 127 / 143 / 129 / 81 | 127 / 143 / 129 / 81 (**delta 0** on every class) |
| Filename-stage rejections | — | 0 (corpus has no unsafe names) |
| Encoding distribution | utf-8 ×480 | utf-8 ×480 (decode-only pass) |
| Determinism mismatches (repeat run) | 0 | 0 |
| Pipeline latency | — | p50 0.0832 ms / p95 2.2862 ms / p99 8.7521 ms |

Why the outcome set is identical: the corpus was probed pre-fix and contains no
binary files, no NUL bytes, no empty files, no >255 names, no traversal names and no
oversized/archives — so the new gates reject exactly what the extension gate already
rejected. The fix closes failure modes the corpus cannot exercise; the synthetic
tests (§11) exercise them instead. Pre-fix originals remain in `01_ingestion_pre_fix/`
(and the untouched evidence set `01_ingestion/` other than the post-fix additions).

## 14. Performance measurements

`V01-65` (n=8 per shape, ingest+commit, same four shapes as the pre-fix baseline
`ingest_perf_baseline.json`):

| Shape | Baseline p50 | Post-fix p50 | Δ p50 | Threshold (5× + 10 ms) |
|---|---|---|---|---|
| small_1kb | 2.198 ms | 1.889 ms | −0.309 ms | pass |
| 1mib | 14.411 ms | 38.100 ms | +23.689 ms | pass |
| near_limit_9_9mib | 104.914 ms | 340.379 ms | +235.465 ms | pass |
| duplicate_reject | 0.339 ms | 0.737 ms | +0.398 ms | pass |

Cause of the large-file growth: `_looks_binary_text` (`ingestion.py:528-540`) scans
every character once (`isprintable()` density check) — the deliberate F4 defence,
mirroring the validator's rule. It is O(bytes) with a small constant (≈25–30 ms/MiB
observed). Small inputs and duplicate rejection are effectively unchanged. No shape
exceeds `baseline × 5 + 10 ms`. Measurement only — not a readiness score.

## 15. Change scope, evidence index, limitations, STOP

**Git verification** (`git status` / `git diff --stat`, final state, HEAD `74ce952`,
nothing committed): modified `backend/app/{api/v1/configurations.py, config.py,
engines/ingestion.py, main.py, models/__init__.py}` and `backend/requirements.txt`
(+567/−165 on the five app files; requirements: pins only, no add/remove). Untracked:
`backend/alembic/versions/004_unique_content_hash.py`, `backend/artifacts/`,
`backend/scripts/`, `backend/tests/validation/`. Frontend modifications
(`package.json`, `tsconfig.json`, `package-lock.json`, `.env.example`) are
pre-existing user work — not touched, not reverted.

**Evidence index** — `artifacts/engine_validation/01_ingestion/`:
`raw_results.jsonl` (98 rows, 97 PASS / 1 NOT APPLICABLE), `dataset_summary_postfix.json`,
`dataset_results_postfix.csv`, `ingest_perf_baseline.json`, `test_results.csv`,
`security_results.csv`, `performance.csv`, `determinism_results.csv`, `summary.json`;
pre-fix snapshot in `01_ingestion_pre_fix/`. Note: `raw_results.jsonl` and the CSVs
were rewritten by post-fix runs (status transitions recorded in §11);
`report_ingestion.py` was intentionally not re-run — its SystemExit on changed
statuses would abort, and the pre-fix reports are preserved as-is in the snapshot.

**Limitations / explicitly out of scope**: corpus cannot reproduce content defects
(§13) — covered synthetically; `device_id` query-vs-form quirk left alone (§8);
V02-33 updated across files (§11); no ZIP extraction feature will exist (§9);
legacy suite failures are pre-existing (§12).

**Finding status roll-up**: F1–F11 **all FIXED**; N1–N10: nine FIXED, N6 DESIGN
DECISION, N9 NOT APPLICABLE (counted within N's ten). Nothing left NOT FIXED.

**Engine 01 work is complete. STOP — Engine 02 is not started.**
