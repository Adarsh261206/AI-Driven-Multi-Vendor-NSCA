# NSCA Air-Gapped / Offline Deployment

The application is designed to support isolated/offline deployment when
deployed with all required dependencies locally. This document states
exactly what was verified — it does not claim every possible deployment
is automatically air-gapped.

## Verified local architecture

```text
Air-Gapped Network
    ↓
Local Frontend (Next.js, next start)
    ↓  NEXT_PUBLIC_API_URL=http://localhost:8000 (no external calls)
Local Backend (FastAPI/uvicorn)
    ↓  local imports only; httpx exists solely inside
       app/ai/providers_openai.py, constructed only when
       OPENAI_API_KEY is set
Local Python analysis engine (in-process)
    ↓  parsers, benchmarks, ML artifacts on disk
Local PostgreSQL (+ local Redis per docker-compose.yml)
    ↓
Local audit ledger (audit_trail table, hash-chained since migration 009)
```

## Verified offline posture (2026-10-04)

- **Database/queue:** `docker-compose.yml` runs `postgres:15` and
  `redis:7` as local services; `DATABASE_URL`/`REDIS_URL` point at them.
  No cloud database is referenced anywhere.
- **AI layer:** `backend/app/ai/client.py:create_ai_client()` uses
  `OpenAIProvider` only when `OPENAI_API_KEY` is set, otherwise falls
  back to the in-process `MockAIProvider` (`app/ai/providers.py`).
  With the key unset (the committed `.env` default), no AI network
  call can be constructed. Proven by
  `scripts/engine_validation/smoke_offline_ledger.py` (MockAI check).
- **Analysis/rules/models:** vendor parsers
  (`app/engines/`), compliance benchmarks (`app/benchmarks/`,
  including Cisco/Juniper/NIST control definitions), and ML artifacts
  (`app/ml/model_artifacts/*.joblib`) all live in the repo and run
  in-process. Cisco/OpenAI URLs in code are static reference strings
  in control metadata or opt-in config defaults — never fetched at
  runtime (only `httpx` user is the OpenAI provider above).
- **Reports:** PDF generation is pure-local `reportlab`; no external
  assets.
- **Frontend:** no CDN script/link tags, no webfont loading
  (`app/layout.tsx` clean; `globals.css` uses the system font stack),
  no analytics/telemetry snippets. The only absolute URL is the
  backend base (`NEXT_PUBLIC_API_URL`, localhost default); one SVG is
  an inline `data:` URI. Icons are the vendored `lucide-react` package.
- **Auth:** local JWT against local Postgres (`app/api/v1/auth.py` +
  `app/security/auth.py`). No external identity provider.

## Offline smoke (key unset)

`scripts/engine_validation/smoke_offline_ledger.py` proves end to end
with `OPENAI_API_KEY` absent: executor analysis → findings → local PDF
→ hash-linked ledger writes → MockAI provider. Result recorded in
`backend/artifacts/engine_validation/12_audit_trail/offline_smoke.json`.

## Operating offline: requirements

1. Build images (or `pip install`/`npm install`) on a connected
   machine, then transfer images/`node_modules`/wheels into the
   isolated network — or run `next start` from a prebuilt `.next`
   output and `uvicorn` from a prepared venv inside the enclave.
2. Keep `OPENAI_API_KEY` unset (or set `AI provider` to a local
   endpoint) so the MockAI/local path stays active. Setting a key
   re-enables the external OpenAI path by design.
3. Provision Postgres + Redis locally (compose file works as-is with
   local image mirrors).
4. Apply Alembic migrations up to `009_trail_hash_chain` on the local
   database (`alembic upgrade head`).

## Limits (stated, not hidden)

- The committed `docker-compose.yml` backend uses `--reload` and
  bind mounts: a development posture. Harden (pinned images, no
  mounts, secrets management) before any production enclave.
- `SECRET_KEY: change-this-in-production` must be replaced.
- This document covers the application layer. Host/network isolation
  (firewall egress rules, DNS sinkholing) is the operator's job and
  is the actual enforcement of "air-gapped" — the app simply makes no
  mandatory external calls to break under it.
