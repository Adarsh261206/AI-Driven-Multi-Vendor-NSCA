"""
Configuration Ingestion Engine

Handles file upload, validation, and storage of network device configurations.
"""

from __future__ import annotations

import hashlib
from typing import Optional
from uuid import UUID, uuid4
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Configuration
from app.config import settings


class IngestionError(Exception):
    """Base exception for ingestion errors"""
    pass


class FileTooLargeError(IngestionError):
    """File exceeds maximum size"""
    pass


class InvalidFileExtensionError(IngestionError):
    """File extension not allowed"""
    pass


class FileDecodeError(IngestionError):
    """Unable to decode file content"""
    pass


class DuplicateConfigurationError(IngestionError):
    """Configuration with same content already exists"""
    pass


class IngestionResult:
    """Result of configuration ingestion"""
    
    def __init__(
        self,
        configuration_id: UUID,
        filename: str,
        content_hash: str,
        size_bytes: int,
        line_count: int,
        encoding: str,
    ):
        self.configuration_id = configuration_id
        self.filename = filename
        self.content_hash = content_hash
        self.size_bytes = size_bytes
        self.line_count = line_count
        self.encoding = encoding


class IngestionEngine:
    """
    Configuration Ingestion Engine
    
    Responsible for:
    - Validating file uploads
    - Calculating content hashes
    - Detecting encoding
    - Storing configurations
    - Preventing duplicates
    """
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def ingest(
        self,
        file_content: bytes,
        filename: str,
        content_type: str,
        device_id: Optional[UUID] = None,
    ) -> IngestionResult:
        """
        Ingest a configuration file
        
        Args:
            file_content: Raw file bytes
            filename: Original filename
            content_type: MIME content type
            device_id: Optional device association
            
        Returns:
            IngestionResult with ingestion details
            
        Raises:
            FileTooLargeError: If file exceeds max size
            InvalidFileExtensionError: If extension not allowed
            FileDecodeError: If unable to decode content
            DuplicateConfigurationError: If content already exists
        """
        # Validate file extension
        self._validate_extension(filename)
        
        # Validate file size
        self._validate_size(file_content)
        
        # Calculate content hash
        content_hash = self._calculate_hash(file_content)
        
        # Check for duplicates
        await self._check_duplicates(content_hash)
        
        # Detect encoding and decode content
        raw_content, encoding = self._decode_content(file_content)
        
        # Count lines
        line_count = len(raw_content.splitlines())
        
        # Create configuration record
        config = Configuration(
            id=uuid4(),
            device_id=device_id,
            filename=filename,
            content_hash=content_hash,
            raw_content=raw_content,
            content_type=content_type or "text/plain",
            size_bytes=len(file_content),
            line_count=line_count,
            encoding=encoding,
            encrypted=False,
        )
        
        self.db.add(config)
        await self.db.flush()
        await self.db.refresh(config)
        
        return IngestionResult(
            configuration_id=config.id,
            filename=filename,
            content_hash=content_hash,
            size_bytes=len(file_content),
            line_count=line_count,
            encoding=encoding,
        )
    
    def _validate_extension(self, filename: str) -> None:
        """Validate file extension is allowed"""
        if not filename or "." not in filename:
            raise InvalidFileExtensionError("Invalid filename")
        
        file_ext = "." + filename.rsplit(".", 1)[-1].lower()
        
        if file_ext not in settings.ALLOWED_EXTENSIONS:
            raise InvalidFileExtensionError(
                f"File extension '{file_ext}' not allowed. "
                f"Allowed: {settings.ALLOWED_EXTENSIONS}"
            )
    
    def _validate_size(self, content: bytes) -> None:
        """Validate file size is within limits"""
        max_size = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
        
        if len(content) > max_size:
            raise FileTooLargeError(
                f"File size ({len(content)} bytes) exceeds "
                f"maximum of {settings.MAX_UPLOAD_SIZE_MB}MB"
            )
    
    def _calculate_hash(self, content: bytes) -> str:
        """Calculate SHA-256 hash of file content"""
        return hashlib.sha256(content).hexdigest()
    
    async def _check_duplicates(self, content_hash: str) -> None:
        """Check if configuration with same content already exists"""
        result = await self.db.execute(
            select(Configuration).where(Configuration.content_hash == content_hash)
        )
        existing = result.scalar_one_or_none()
        
        if existing:
            raise DuplicateConfigurationError(
                f"Configuration with same content already exists "
                f"(ID: {existing.id})"
            )
    
    def _decode_content(self, content: bytes) -> tuple[str, str]:
        """
        Decode file content with encoding detection
        
        Returns:
            Tuple of (decoded_content, encoding_used)
        """
        # Try UTF-8 first
        try:
            return content.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            pass
        
        # Try Latin-1 (always succeeds)
        try:
            return content.decode("latin-1"), "latin-1"
        except UnicodeDecodeError:
            pass
        
        # Try CP-1252 (Windows)
        try:
            return content.decode("cp-1252"), "cp-1252"
        except UnicodeDecodeError:
            pass
        
        raise FileDecodeError("Unable to decode file content with any supported encoding")
