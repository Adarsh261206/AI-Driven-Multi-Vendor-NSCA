# ENGINE_READINESS_SUMMARY — Engine 01 · Configuration Ingestion

**Verdict: PARTIAL** · 71 evidence rows · 480-file dataset sweep · `backend/app/` unchanged

Full detail: [`ENGINE_REPORT.md`](ENGINE_REPORT.md) · raw evidence: `raw_results.jsonl`,
`summary.json`, `test_results.csv`, `dataset_results.csv`, `dataset_summary.json`,
`performance.csv`, `determinism_results.csv`, `security_results.csv`.

## Status by category

| A | B | C | D | E | F | G | H | I | J | K |
|---|---|---|---|---|---|---|---|---|---|---|
| PASS | PASS | PASS | PASS ×19 / **FAIL** / PARTIAL | PASS ×6 / **FAIL ×2** / N/A | PARTIAL ×11 | PASS | PASS | PASS ×3 / **FAIL** | PASS | PASS / **FAIL** / PARTIAL |

Totals: PASS 52 · PARTIAL 13 · FAIL 5 · NOT APPLICABLE 1.
Classifications: CONFIRMED BEHAVIOR 60 · DESIGN LIMITATION 6 · MISSING 4 · N/A 1.

## What works

- SHA-256 hashing matches the reference for every input tested (V01-01).
- 10 MiB limit is enforced with a strict `>` boundary (10485760 accepted, 10485761 rejected).
- Extension allow-list, oversize and duplicate failures all raise typed `IngestionError` subclasses with non-empty messages.
- Determinism: 0 mismatches across 3 independent engine instances and 2 full passes over 480 real files.
- Performance (measurements only): decode+sha256 p50 0.72 ms at 1 MiB (1387 MB/s median); dataset p99 0.17 ms.
- Validation failures occur before any `db.add()` — no partial rows are persisted.

## What blocks readiness

| # | Finding | Class |
|---|---|---|
| F9 | The engine is imported by **nothing**; the production upload path (`configurations.py:67-144`) re-implements the same logic with different duplicate, decode and extension semantics | DESIGN LIMITATION |
| F2 | Filename > 255 chars escapes as untyped `sqlalchemy.exc.DBAPIError` instead of `IngestionError` | MISSING |
| F3 | NUL bytes in content fail at PostgreSQL as `CharacterNotInRepertoireError`, escaping `ingest()` untyped | MISSING |
| F1 | `FileDecodeError` is unreachable dead code — `latin-1` accepts every byte, so binary input silently becomes text | MISSING |

## Also confirmed

| # | Finding | Class |
|---|---|---|
| F4 | No binary/magic-byte check at ingestion (the validator's `BINARY_CONTENT` runs much later) | DESIGN LIMITATION |
| F5 | `.zip` is allow-listed but never extracted; size is checked on compressed bytes | DESIGN LIMITATION |
| F6 | Traversal-shaped and NUL filenames accepted verbatim; never normalised to a basename | CONFIRMED BEHAVIOR |
| F7 | `content_type` is an unvalidated caller string | CONFIRMED BEHAVIOR |
| F8 | Zero-byte configs accepted with `line_count=0` (no explicit contract) | DESIGN LIMITATION |
| F10 | `ingest()` returns an id while `AuditExecutor.execute()` requires `config_content: str`; hand-off is a DB read neither module performs | DESIGN LIMITATION |
| F11 | `ingest()` never flushes; durability depends on the caller committing | CONFIRMED BEHAVIOR |

## Dataset reality check

480 files / 11,584,713 bytes → **256 (53.3%) would actually be accepted** by `ingest()`:
143 rejected on extension (29.8%) and 81 rejected as duplicate content.
Largest file 491,015 B (4.7% of the limit); 0 size, binary, NUL or oversize-name cases in this corpus.

## Hypotheses

H1–H12 all **CONFIRMED** (see `summary.json` → `hypotheses`).

## Out of scope / not verifiable

- Upload endpoint divergence recorded as an integration observation only (agreed scope).
- Vendor syntax handling — NOT APPLICABLE (ingestion is vendor-agnostic).
- ML evaluation — deferred until all 12 engines are validated.

---

**Bro, ENGINE 01 (Configuration Ingestion Engine) validation is complete. `ENGINE_READINESS_SUMMARY.md` is ready for review. Do you want me to proceed to the next engine (Engine 02 — Validation Engine)?**
