from fastapi import APIRouter

from app.api.v1 import auth, devices, configurations, audits, findings, compliance, training, reports, audit_execution, audit_trail

api_router = APIRouter()

# Include routers
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
api_router.include_router(configurations.router, prefix="/configurations", tags=["configurations"])
api_router.include_router(audits.router, prefix="/audits", tags=["audits"])
api_router.include_router(audit_execution.router, prefix="/audit-execution", tags=["audit-execution"])
api_router.include_router(findings.router, prefix="/findings", tags=["findings"])
api_router.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
api_router.include_router(training.router, prefix="/training", tags=["training"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(audit_trail.router, prefix="/audit-trail", tags=["audit-trail"])
