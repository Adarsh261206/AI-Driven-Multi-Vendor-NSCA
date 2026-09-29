# AI-Driven Multi-Vendor Network Security Compliance Auditor

**Problem Statement ID:** 26155
**Organization:** National Technical Research Organisation (NTRO)
**Theme:** Blockchain & Cybersecurity

## Overview

An adaptive, AI-augmented platform that understands network security configurations across any vendor, provides deterministic compliance evaluation, and learns continuously from human expertise.

## Key Features

- **Multi-Vendor Support:** Cisco, Fortinet, Juniper (MVP)
- **Compliance Frameworks:** CIS Benchmarks, NIST SP 800-53
- **Adaptive Learning:** Teach the system unknown configurations
- **Evidence-First Design:** Every finding is fully traceable
- **Deterministic Compliance:** AI assists, rules decide
- **Professional Reporting:** PDF reports with executive summary

## Architecture

- **Frontend:** Next.js + TypeScript
- **Backend:** Python + FastAPI
- **Database:** PostgreSQL
- **Cache:** Redis
- **AI:** OpenAI GPT-4 (MVP)
- **Containerization:** Docker

## Documentation

- [Project Master Spec](docs/PROJECT_MASTER_SPEC.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Data Model](docs/DATA_MODEL.md)
- [API Contracts](docs/API_CONTRACTS.md)
- [Compliance Model](docs/COMPLIANCE_MODEL.md)
- [AI Architecture](docs/AI_ARCHITECTURE.md)
- [Development Roadmap](docs/DEVELOPMENT_ROADMAP.md)

## Quick Start

### Prerequisites

- Python 3.11+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+
- Docker (optional)

### Development Setup

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd "SIH 2026"
   ```

2. Start services with Docker:
   ```bash
   docker-compose up -d
   ```

3. Set up backend:
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   alembic upgrade head
   uvicorn app.main:app --reload
   ```

4. Set up frontend:
   ```bash
   cd frontend
   npm install
   npm run dev
   ```

5. Access the application:
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

## Development

See [Development Roadmap](docs/DEVELOPMENT_ROADMAP.md) for detailed milestones and timeline.

## License

This project is for Smart India Hackathon 2026.
