# ConfigShield

**An AI-Driven, Vendor-Agnostic Network Security Compliance Auditor**

**Problem Statement ID:** 26155 · **Organization:** National Technical Research Organisation (NTRO) · **Theme:** Blockchain & Cybersecurity

---

## What is ConfigShield?

Enterprise networks today include 150 or more devices from a variety of vendors such as Cisco, Juniper, Fortinet, Palo Alto and the newer white-box ecosystem including SONiC, and yet none of these devices make it easy to audit their configurations. In order to comply with the CIS Benchmarks, NIST SP 800-53, DISA STIGs and ISO/IEC 27001, enterprises have to rely either on manual methods which are time-consuming and take several weeks to carry out, or on costly and inflexible enterprise-grade tools that fail dramatically when faced with a device in an unfamiliar format.

**ConfigShield is a compliance solution that does not depend on any particular vendor** and uses AI and natural language processing to convert the configuration formats of any vendor into a single **Unified Security Model**; it is designed to understand new syntaxes through a **no-code Human-in-the-Loop interface**, so that there is no need for continual changes to the backend code. It features a **dual compliance engine** which runs the CIS and STIG benchmarks (the technical standards), cross-referencing them with NIST and ISO/IEC, while at the same time comparing them against the user's own **baseline policy** for the scope of their network in order to tell the difference between what they are required to report to regulators and what specifically applies to their network. Any checks that cannot be automatically deduced from the device configuration are clearly listed as **Manual Review Required** in order to ensure that auditors have confidence.

The PDF report is based on a **risk priority approach** and includes device-specific remediation scripts which have each been **hashed and recorded on a blockchain ledger** in order to enable tamper-proof auditing by the verifiers. The modular codebase — this uses Netmiko/NAPALM for gathering configuration data, has a FastAPI/Python backend, relies on PostgreSQL and features a central GUI — can be easily scaled to new devices and vendors, as well as allow new frameworks (such as PCI DSS, RBI/CERT-In etc) to be added without any modifications to the core architecture.

ConfigShield is able to reduce the amount of money and man-hours that BFSI, government, telecom and enterprise clients spend on audits by turning what used to be a weeks-long auditing process based on extensive manual checks and paperwork into one that is now fully automated and takes just one day while at the same time ensuring continued security and compliance in heterogeneous network environments.

---

## Key Features

- **Vendor-Agnostic Parsing** — Cisco IOS XE, Juniper JUNOS and any CLI format normalize into one Unified Security Model (28 canonical paths)
- **Dual Compliance Engine** — CIS + STIG benchmarks cross-referenced with NIST and ISO/IEC
- **Company Baseline** — org-level scope configured once at onboarding; audits compare against *your* policy, not just generic benchmarks
- **Human-in-the-Loop Learning** — teach the system unknown syntaxes through the UI — no backend code changes
- **Live Pipeline UI** — every audit step (validate → detect → parse → normalize → evaluate → findings → report) streams live progress
- **Fleet-Scoped Dedup** — identical golden configs on 100 switches upload once per device; same-device replays are idempotent
- **Evidence-First** — every PASS / FAIL / REVIEW / MANUAL REVIEW verdict carries its evidence chain
- **Risk-Prioritized PDF Reports** — device-specific remediation scripts, hashed and recorded on a blockchain ledger for tamper-proof audit
- **Deterministic Compliance** — AI assists, rules decide

---

## Architecture

A full Architecture Document with verified diagrams is at **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)** — it includes system architecture, audit pipeline workflow, run-audit sequence, data flow, and execution lifecycle (each diagram passed automated validation + browser checks):

| Diagram | Static | Interactive (motion · themes · export) |
|---|---|---|
| System Architecture | [SVG](docs/diagrams/configshield-architecture.svg) | [HTML](.archify/architecture-configshield-20260930-162929/configshield-architecture.html) |
| Audit Pipeline Workflow | [SVG](docs/diagrams/configshield-workflow.svg) | [HTML](.archify/workflow-audit-pipeline-20260930-162929/configshield-audit-workflow.html) |
| Run Audit — Sequence | [SVG](docs/diagrams/configshield-sequence.svg) | [HTML](.archify/sequence-execute-audit-20260930-162929/configshield-execute-sequence.html) |
| Data Flow | [SVG](docs/diagrams/configshield-dataflow.svg) | [HTML](.archify/dataflow-config-to-report-20260930-162929/configshield-dataflow.html) |
| Execution Lifecycle | [SVG](docs/diagrams/configshield-execution-lifecycle.svg) | [HTML](.archify/lifecycle-audit-execution-20260930-162929/configshield-execution-lifecycle.html) |

### Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js (React + TypeScript) |
| Backend | Python + FastAPI |
| Queue / Worker | Celery + Redis (durable execution state machine) |
| Database | PostgreSQL (async via asyncpg + SQLAlchemy) |
| AI / ML | Scikit-learn (TF-IDF + LogisticRegression vendor detection), optional LLM provider (OpenAI-compatible) |
| Migrations | Alembic |
| Device Collection | Netmiko / NAPALM (planned integration layer) |

### Repository Layout

```
├── backend/
│   ├── app/
│   │   ├── api/v1/          # FastAPI routers (auth, devices, configurations,
│   │   │                    #   audit-execution, baseline, reports, findings, training)
│   │   ├── engines/         # ingestion, detection (ML), parsing, normalization,
│   │   │                    #   compliance (CIS), reporting
│   │   ├── services/        # execution state machine, scope (ownership), baseline
│   │   ├── models/          # SQLAlchemy models
│   │   ├── tasks.py         # Celery worker entry
│   │   └── celery_app.py
│   ├── alembic/versions/    # migrations 001–016 (single head)
│   ├── tests/               # 1847+ tests
│   └── requirements.txt
├── frontend/
│   ├── app/                 # Next.js App Router pages (devices, audit, reports, settings…)
│   ├── lib/                 # API client, types, formatting
│   └── hooks/               # auth, dashboard data
├── docs/
│   ├── ARCHITECTURE.md      # Architecture Document with diagrams
│   └── diagrams/            # SVG diagram exports
└── .archify/                # interactive diagram sources
```

---

## Setup Instructions (Step by Step)

### Prerequisites

Install these first on your machine:

| Requirement | Version | How to check |
|---|---|---|
| Python | 3.11+ | `python3 --version` |
| Node.js | 18+ | `node --version` |
| npm | 9+ | `npm --version` |
| PostgreSQL | 14+ | `psql --version` |
| Redis | 7+ | `redis-cli ping` (should reply `PONG`) |

> **macOS (Homebrew) quick install:** `brew install python node postgresql@14 redis`

---

### Step 1 — Clone the repository

```bash
git clone https://github.com/Adarsh261206/AI-Driven-Multi-Vendor-NSCA.git
cd AI-Driven-Multi-Vendor-NSCA
```

### Step 2 — Start PostgreSQL and Redis

**Option A (recommended): Docker**

```bash
docker compose up -d          # starts postgres + redis
```

**Option B (local installs):**

```bash
brew services start postgresql@14
brew services start redis

# create the application database (once)
createdb compliance_auditor
```

### Step 3 — Set up the Backend

```bash
cd backend

# 1. Create a virtual environment and activate it
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 2. Install dependencies
pip install -r requirements.txt

# 3. Create the environment file from the template
cp .env.example .env
#    Edit .env if needed:
#    - DATABASE_URL=postgresql+asyncpg://postgres:postgres@localhost:5432/compliance_auditor
#    - REDIS_URL=redis://localhost:6379
#    - (optional) OPENAI_API_KEY=sk-...   # without it, a built-in provider is used

# 4. Run database migrations (single head: 016)
alembic upgrade head

# 5. (Optional, recommended for judges) Seed a demo admin in one command
python scripts/seed_demo.py
#    Signs in at http://localhost:3000 with:
#    admin@configshield.local / Admin12345
```

### Step 4 — Start the Celery Worker

The worker runs the actual audit pipeline. **Keep it running in its own terminal.**

```bash
cd backend
source venv/bin/activate
celery -A app.celery_app worker -l info --pool=solo
```

> `--pool=solo` is recommended on macOS/Windows (avoids fork issues with async code).

### Step 5 — Start the Backend API

**In a second terminal:**

```bash
cd backend
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Verify: open http://localhost:8000/docs — the Swagger UI should load.

### Step 6 — Set up the Frontend

**In a third terminal:**

```bash
cd frontend

# 1. Install dependencies
npm install

# 2. Create the environment file
cp .env.example .env.local      # NEXT_PUBLIC_API_URL=http://localhost:8000

# 3. Start the dev server
npm run dev
```

### Step 7 — Log in and use ConfigShield

Open **http://localhost:3000** and create your account:

- Click **Register** → enter your name, email, and a password (min 8 characters).
- Register with `role: admin` for full access (or create an admin via the API):
  ```bash
  curl -X POST http://localhost:8000/api/v1/auth/register \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@company.com","password":"Admin@123","full_name":"Admin","role":"admin"}'
  ```
- First run: the **Company Baseline onboarding** wizard appears — configure your org-level controls (or skip).
- Create a device → upload its configuration (bound to the device) → click **Run Audit** → watch the live pipeline → open the report.
- Fastest demo: upload `demo-configs/cisco-good.cfg` (or `juniper-good.conf`) and run an audit — findings, remediation plans, and the hash-chained audit ledger (`/audit-log`) populate automatically.

### What's running where (summary)

| Service | Command | URL |
|---|---|---|
| Frontend | `npm run dev` (in `frontend/`) | http://localhost:3000 |
| Backend API | `uvicorn app.main:app --port 8000` | http://localhost:8000 |
| API Docs (Swagger) | — | http://localhost:8000/docs |
| Celery Worker | `celery -A app.celery_app worker --pool=solo` | — |
| PostgreSQL | `docker compose up -d` / `brew services start postgresql@14` | localhost:5432 |
| Redis | `docker compose up -d` / `brew services start redis` | localhost:6379 |

---

## Running the Tests

```bash
cd backend
source venv/bin/activate

# Full backend test suite (1847+ tests)
pytest tests/ -q

# Targeted suites
pytest tests/test_device_security.py        # ownership + fleet dedup
pytest tests/test_baseline.py               # company baseline
pytest tests/validation/test_v01_ingestion.py  # ingestion engine validation
```

Frontend type-check and build:

```bash
cd frontend
npx tsc --noEmit
npm run build
```

---

## Documentation

- [Architecture Document](docs/ARCHITECTURE.md) — system architecture, workflows, sequence, data flow, lifecycle (with verified diagrams)
- [Project Master Spec](docs/PROJECT_MASTER_SPEC.md)
- [Data Model](docs/DATA_MODEL.md)
- [API Contracts](docs/API_CONTRACTS.md)
- [Compliance Model](docs/COMPLIANCE_MODEL.md)
- [AI Architecture](docs/AI_ARCHITECTURE.md)
- [Development Roadmap](docs/DEVELOPMENT_ROADMAP.md)

---

## License

This project is built for **Smart India Hackathon 2026** — Problem Statement 26155 (NTRO — Blockchain & Cybersecurity).