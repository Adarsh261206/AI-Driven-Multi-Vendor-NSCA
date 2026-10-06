from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import User, AuditAction
from app.repositories.audit_trail import AuditTrailRepository
from app.schemas import UserCreate, UserLogin, UserResponse, TokenResponse, TokenRefresh
from app.security.auth import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
)

router = APIRouter()


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(request: UserCreate, db: AsyncSession = Depends(get_db)):
    """Register a new user"""
    # Check if user already exists
    result = await db.execute(select(User).where(User.email == request.email))
    existing_user = result.scalar_one_or_none()
    
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )
    
    # Create new user
    user = User(
        email=request.email,
        password_hash=hash_password(request.password),
        full_name=request.full_name,
        role="auditor",
    )
    
    db.add(user)
    await db.flush()
    await db.refresh(user)
    
    return user


@router.post("/login", response_model=TokenResponse)
async def login(request: UserLogin, db: AsyncSession = Depends(get_db)):
    """Login user and return tokens"""
    # Find user by email
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(request.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled"
        )
    
    # Create tokens
    access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
    refresh_token = create_refresh_token(data={"sub": str(user.id), "email": user.email})

    # Session observability (best-effort by design: a trail write must
    # never decide whether a legitimate user can sign in).
    try:
        trail = AuditTrailRepository(db)
        await trail.log(
            action=AuditAction.USER_LOGIN,
            entity_type="user",
            entity_id=str(user.id),
            user_id=str(user.id),
            details={"method": "password"},
        )
        await db.flush()
    except Exception:
        pass

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=900,
    )


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user),
                 db: AsyncSession = Depends(get_db)):
    """Sign out (observability only).

    Tokens are stateless JWTs and there is deliberately no revocation
    infrastructure; the client discards its tokens. This endpoint exists
    so the sign-out itself is recorded in the audit ledger. Best-effort
    like login: always succeeds from the caller's perspective.
    """
    try:
        trail = AuditTrailRepository(db)
        await trail.log(
            action=AuditAction.USER_LOGOUT,
            entity_type="user",
            entity_id=str(current_user.id),
            user_id=str(current_user.id),
            details={},
        )
        await db.flush()
    except Exception:
        pass
    return {"success": True}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(request: TokenRefresh, db: AsyncSession = Depends(get_db)):
    """Refresh access token using refresh token"""
    # Decode refresh token
    payload = decode_token(request.refresh_token)
    
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type"
        )
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    # Get user
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive"
        )
    
    # Create new tokens
    access_token = create_access_token(data={"sub": str(user.id), "email": user.email})
    refresh_token = create_refresh_token(data={"sub": str(user.id), "email": user.email})
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=900,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information"""
    return current_user
