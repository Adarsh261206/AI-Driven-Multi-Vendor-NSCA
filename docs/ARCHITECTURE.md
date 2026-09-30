# ConfigShield — Architecture Document

> **ConfigShield: An AI-Driven, Vendor-Agnostic Network Security Compliance Auditor**
>
> Verified against repository commit `6f2395b9b2a0bfe42c91b93cfa20933b205b240c` ·
> Diagrams generated with Archify — every diagram passed automated validate +
> browser-check gates before inclusion.

---

## 1. Product Overview

Enterprise networks today include 150 or more devices from a variety of vendors such as
Cisco, Juniper, Fortinet, Palo Alto and the newer white-box ecosystem including SONiC, and
yet none of these devices make it easy to audit their configurations. In order to comply
with the CIS Benchmarks, NIST SP 800-53, DISA STIGs and ISO/IEC 27001, enterprises have to
rely either on manual methods which are time-consuming and take several weeks to carry out,
or on costly and inflexible enterprise-grade tools that fail dramatically when faced with a
device in an unfamiliar format.

ConfigShield is a compliance solution that **does not depend on any particular vendor** and
uses AI and natural language processing to convert the configuration formats of any vendor
into a single **Unified Security Model**; it is designed to understand new syntaxes through
a **no-code Human-in-the-Loop interface**, so that there is no need for continual changes to
the backend code. It features a **dual compliance engine** which runs the CIS and STIG
benchmarks (the technical standards), cross-referencing them with NIST and ISO/IEC, while at
the same time comparing them against the user's own **baseline policy** for the scope of
their network in order to tell the difference between what they are required to report to
regulators and what specifically applies to their network. Any checks that cannot be
automatically deduced from the device configuration are clearly listed as **Manual Review
Required** in order to ensure that auditors have confidence.

The PDF report is based on a **risk priority approach** and includes device-specific
remediation scripts which have each been **hashed and recorded on a blockchain ledger** in
order to enable tamper-proof auditing by the verifiers. The modular codebase — this uses
Netmiko/NAPALM for gathering configuration data, has a FastAPI/Python backend, relies on
PostgreSQL and features a central GUI — can be easily scaled to new devices and vendors, as
well as allow new frameworks (such as PCI DSS, RBI/CERT-In etc) to be added without any
modifications to the core architecture.

ConfigShield is able to reduce the amount of money and man-hours that BFSI, government,
telecom and enterprise clients spend on audits by turning what used to be a weeks-long
auditing process based on extensive manual checks and paperwork into one that is now fully
automated and takes just one day while at the same time ensuring continued security and
compliance in heterogeneous network environments.

---

## 2. System Architecture

The platform is split across four runtime roles: a **Next.js console** (UI), a **FastAPI
gateway** (all `/api/v1` routers), a **Celery worker** (durable execution + engine pipeline)
and **PostgreSQL** (source of truth). Every ownership decision is enforced server-side by
the Scope Gate; a dedicated `audit_progress` row carries live pipeline progress across the
worker/API process split without ever locking the execution row.

<img src="diagrams/configshield-architecture.svg" alt="ConfigShield System Architecture" width="100%"/>

**Interactive version:** [open in browser](../.archify/architecture-configshield-20260930-162929/configshield-architecture.html)
(motion, dark/light themes, PNG/JPEG/WebP/SVG/WebM export)

### 2.1 Key components

| Component | Role | Evidence |
|---|---|---|
| **ConfigShield UI** | Next.js console — device inventory, audit wizard, live pipeline view, reports, baseline settings, training | `frontend/app/audit/new/page.tsx`, `frontend/app/audit/[id]/page.tsx` |
| **FastAPI Gateway** | All `/api/v1` routers — auth, devices, configurations, audit-execution, baseline, reports, findings, training | `backend/app/main.py:83` |
| **Scope Gate** | Server-enforced ownership + lifecycle (owned device, active, configs auditable) | `backend/app/services/scope.py:31,62,180` |
| **Baseline Service** | Company Baseline — org-level control scope, resolve-for-audit, one active baseline, snapshot on audit | `backend/app/api/v1/baseline.py:366` |
| **Celery Broker** | Durable task queue (Redis) | `backend/app/celery_app.py:19` |
| **Celery Worker** | Atomic claim, lease heartbeat, retries, runs the full pipeline | `backend/app/tasks.py:32`, `backend/app/services/execution.py:118` |
| **Compliance Pipeline** | Validate → Detect (ML) → Parse → Normalize → Evaluate (CIS) → Findings → Report | `backend/app/api/v1/audit_execution.py:247`, `backend/app/engines/compliance/executor.py:121` |
| **PostgreSQL** | configurations (unique `(device_id, content_hash)`), audits, executions, audit_progress, compliance_results, findings, baselines | `backend/app/models/__init__.py:158,463,500` |
| **Reporting Engine** | PDF report — risk priority, remediation scripts, COMPANY BASELINE + FULL CIS sections | `backend/app/engines/reporting.py:320` |

---

## 3. Audit Pipeline Workflow

An audit moves through upload → scope gate → durable queue → worker claim → the seven
engine steps → live outcome. Fleet reality is respected: identical golden configs store once
**per device** (dedup scoped to `(device, content_hash)`), same-device replays are
idempotent, and a failed attempt retries as a **new row** (attempt+1) — history is never
overwritten.

<img src="diagrams/configshield-workflow.svg" alt="Audit Pipeline Workflow" width="100%"/>

**Interactive version:** [open in browser](../.archify/workflow-audit-pipeline-20260930-162929/configshield-audit-workflow.html)

---

## 4. Run Audit — Queue Roundtrip (Sequence)

The sequence shows the exact request lifecycle: upload bound to a device → execute creates
a durable execution row → task published → worker claims atomically (duplicate delivery
exits safely) → the pipeline commits step/progress snapshots to `audit_progress` → the UI
polls every 800 ms → completion is a CAS that honors a concurrent cancel.

<img src="diagrams/configshield-sequence.svg" alt="Run Audit — Queue Roundtrip" width="100%"/>

**Interactive version:** [open in browser](../.archify/sequence-execute-audit-20260930-162929/configshield-execute-sequence.html)

---

## 5. Data Flow — Configuration → Security State → Report

Raw bytes are validated and hashed exactly once at ingestion; a single canonical
**Unified Security Model** (28 universal paths) feeds every control evaluation. Evidence
chains are persisted per verdict (ML provenance, parse diagnostics, evidence + remediation),
and the Company Baseline is a scope projection over stored CIS results — never a second
evaluation.

<img src="diagrams/configshield-dataflow.svg" alt="Configuration → Security State → Report" width="100%"/>

**Interactive version:** [open in browser](../.archify/dataflow-config-to-report-20260930-162929/configshield-dataflow.html)

---

## 6. Audit Execution Lifecycle

The execution state machine is durable and worker-owned: `queued → running → completed`
with cooperative cancellation (`cancel_requested → cancelled`), lease-based recovery of
worker-lost runs, and retries that always create a fresh row.

<img src="diagrams/configshield-execution-lifecycle.svg" alt="Audit Execution Lifecycle" width="100%"/>

**Interactive version:** [open in browser](../.archify/lifecycle-audit-execution-20260930-162929/configshield-execution-lifecycle.html)

---

## 7. Design Contracts (invariants)

- **Parse once, normalize once, build canonical security state once.** Company Baseline is a
  scope projection over stored CIS results — it is never a second benchmark or a score
  optimizer.
- **Ownership is server-enforced.** The org is derived from the authenticated user; no
  client-supplied org/device/owner IDs are trusted. A non-admin auditor audits only
  configurations linked to their own devices.
- **Dedup is fleet-aware.** Duplicate identity = `(device_id, content_hash)`. Same bytes on
  a second device store a new row; same device replays idempotently; device-less uploads
  keep global replay semantics — all DB-guarded (composite + partial unique indexes).
- **Every scope is DB-enforced, never pre-check-only.** Race guards exist for both
  device-bound and unlinked uploads.
- **Progress never blocks the pipeline.** Live steps/logs/progress commit to the dedicated
  `audit_progress` row from a lightweight session; the execution row is only ever touched by
  the pipeline's own transaction (row lock), so there is no cross-session lock conflict.
- **Lifecycle is durable and honest.** One execution row per attempt; retry = new row;
  terminal states are never reused; cancellation is cooperative at checkpoints.
- **Framework layering.** NIST/ISO/STIG are separate layers — the system never invents
  CIS↔NIST mappings, control definitions, evidence, or findings.