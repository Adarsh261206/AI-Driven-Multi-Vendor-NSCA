from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager

from app.config import settings
from app.api.v1.router import api_router
from app.database import init_db, close_db
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.security import SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    await init_db()
    yield
    await close_db()


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="AI-Driven Multi-Vendor Network Security Compliance Auditor",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    lifespan=lifespan,
)

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    RateLimitMiddleware,
    requests_per_minute=settings.RATE_LIMIT_PER_MINUTE,
    requests_per_hour=settings.RATE_LIMIT_PER_HOUR,
    burst_size=settings.RATE_LIMIT_BURST,
)

# Multipart framing allowance above MAX_UPLOAD_SIZE_MB: boundary
# markers plus per-part headers (filename, content-type). A declared
# body size beyond this cannot possibly hold an acceptable upload, so
# oversized requests are rejected here — before Starlette parses the
# multipart body into a spooled temp file — instead of only after the
# body has been read (E01 N10). Registered before CORSMiddleware so
# CORS stays the outermost middleware.
_UPLOAD_FRAMING_ALLOWANCE_BYTES = 64 * 1024


@app.middleware("http")
async def reject_oversized_upload_requests(request, call_next):
    if request.method == "POST" and request.url.path.endswith(
        "/configurations/upload"
    ):
        length = request.headers.get("content-length")
        if length and length.isdigit():
            limit = (
                settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
                + _UPLOAD_FRAMING_ALLOWANCE_BYTES
            )
            if int(length) > limit:
                return JSONResponse(
                    status_code=413,
                    content={
                        "detail": (
                            f"File size exceeds maximum of "
                            f"{settings.MAX_UPLOAD_SIZE_MB}MB"
                        )
                    },
                )
    return await call_next(request)

# CORSMiddleware must be registered LAST so it is the OUTERMOST middleware.
# Middleware added before it (e.g. rate limiting) returns errors without CORS
# headers, which the browser misreports as CORS failures.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "service": settings.APP_NAME,
    }


@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "docs": "/docs",
    }
