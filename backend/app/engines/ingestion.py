"""
Configuration Ingestion Engine

Single source of truth for ingesting network device configuration files.
The production upload endpoint (app/api/v1/configurations.py) delegates
to this module; no ingestion rule is implemented anywhere else.

Ingestion contract (E01 fix decisions):

* Typed errors — every predictable input problem raises an
  IngestionError subclass; raw database or Python exceptions never
  escape for invalid input.
* Encoding strategy — strict UTF-8 first, strict cp-1252 fallback,
  then FileDecodeError (reachable). Arbitrary binary data is never
  silently converted into configuration text: NUL bytes, known binary
  file signatures and a non-printable density heuristic (the same rule
  ValidationEngine uses for BINARY_CONTENT) reject content before any
  database work.
* Filenames — must be printable strings of at most 255 characters
  (Configuration.filename String(255)) without path separators, drive
  letters or control characters; the extension must be on the
  settings.ALLOWED_EXTENSIONS allow-list.
* ZIP archives are NOT supported. `.zip` was removed from
  settings.ALLOWED_EXTENSIONS (F5/N7/N9 decision): the API contract
  persists exactly one Configuration row per upload, no safe bounded
  multi-member extraction path exists, and the validation corpus
  contains no archives. Archives are rejected at the extension gate
  with a typed error instead of being stored as mojibake text.
* content_type — advisory metadata only. It is syntax-validated and
  length-bounded (String(50)) but never authoritative: the validated
  extension and the actual bytes decide ingestion (F7).
* Duplicate identity — byte-level. content_hash = SHA-256 of the raw
  upload bytes with a UNIQUE database constraint; the application-level
  pre-check is a friendly fast path only (N5/N6). Logical-content
  identity would require normalization semantics inside ingestion, so
  byte identity is retained deliberately.
* Empty / whitespace-only content is rejected as meaningless (N8).
  Comment-only configurations remain valid content.
* Transactions — ingest() flushes but never commits. The caller owns
  the transaction; in the FastAPI stack get_db commits after the
  request handler returns and rolls back on exception. Durability
  therefore requires the caller to commit; a rollback after a
  successful ingest() discards the row by design (F11).
* Downstream hand-off — IngestionResult carries the decoded content
  for same-request consumers; cross-request consumers (the audit
  pipeline) read Configuration.raw_content by id. The persisted row is
  the single source of truth (F10).
"""

from __future__ import annotations

import hashlib
import re
from typing import Optional
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Configuration, Device
from app.config import settings


# Column bounds enforced here so violations are typed, not DB errors.
MAX_FILENAME_LENGTH = 255       # Configuration.filename String(255)
MAX_CONTENT_TYPE_LENGTH = 50    # Configuration.content_type String(50)

# type/subtype with optional "; parameter" suffix (e.g. "text/plain; charset=utf-8")
_MIME_TYPE_RE = re.compile(r"^[A-Za-z0-9!#$&^_+\-.]+/[A-Za-z0-9!#$&^_+\-.]+")

# Unambiguous binary file signatures (contain control bytes or fixed
# format markers that configuration text never starts with). Content
# starting with one of these is not configuration text (F4).
_BINARY_MAGIC_PREFIXES: tuple[bytes, ...] = (
    b"%PDF-",
    b"\x7fELF",
    b"\x89PNG\r\n\x1a\n",
    b"GIF87a",
    b"GIF89a",
    b"\xff\xd8\xff",
    b"\x1f\x8b",
    b"\xd0\xcf\x11\xe0",
    b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\xca\xfe\xba\xbe",
)


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
    """Unable to decode file content with any supported encoding"""
    pass


class DuplicateConfigurationError(IngestionError):
    """Configuration with identical raw bytes already exists"""

    def __init__(
        self,
        message: str,
        configuration_id: Optional[UUID] = None,
        content_hash: Optional[str] = None,
    ):
        super().__init__(message)
        self.configuration_id = configuration_id
        self.content_hash = content_hash


class InvalidFilenameError(IngestionError):
    """Filename fails safety validation (type/length/printability/path shape)"""
    pass


class InvalidContentError(IngestionError):
    """Content fails policy validation (type/NUL/binary/empty/whitespace-only)"""
    pass


class InvalidContentTypeError(IngestionError):
    """content_type is malformed, non-string, or exceeds String(50)"""
    pass


class InvalidDeviceError(IngestionError):
    """device_id is invalid or references a nonexistent device"""
    pass


class IngestionResult:
    """Result of configuration ingestion.

    `content` is the decoded text exactly as persisted into
    Configuration.raw_content, so same-request consumers can hand it to
    the audit pipeline without re-reading or re-decoding anything (F10).
    """

    def __init__(
        self,
        configuration_id: UUID,
        filename: str,
        content_hash: str,
        size_bytes: int,
        line_count: int,
        encoding: str,
        content: str,
    ):
        self.configuration_id = configuration_id
        self.filename = filename
        self.content_hash = content_hash
        self.size_bytes = size_bytes
        self.line_count = line_count
        self.encoding = encoding
        self.content = content


class IngestionEngine:
    """
    Configuration Ingestion Engine

    Responsible for:
    - Validating filename / extension / size / content type
    - Rejecting NUL, binary and empty-or-whitespace-only content
    - Decoding with an explicit deterministic encoding strategy
    - Calculating content hashes and preventing duplicates
    - Validating the optional device association
    - Persisting the Configuration row (flush; caller commits)
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
        Ingest a configuration file.

        Args:
            file_content: Raw file bytes (bytearray accepted, coerced)
            filename: Original filename (safety-validated)
            content_type: Advisory MIME type (syntax-validated, never
                authoritative for ingestion decisions)
            device_id: Optional device association (must exist if given)

        Returns:
            IngestionResult with ingestion details including the
            decoded content

        Raises:
            InvalidContentError: file_content is not bytes, contains
                NUL, is binary-looking, or is empty/whitespace-only
            InvalidFilenameError: filename is unsafe or longer than 255
            InvalidFileExtensionError: extension not allow-listed
            FileTooLargeError: file exceeds max size
            InvalidContentTypeError: content_type malformed or >50 chars
            FileDecodeError: neither UTF-8 nor cp-1252 decodes the bytes
            DuplicateConfigurationError: identical bytes already stored
            InvalidDeviceError: device_id invalid or nonexistent

        Transaction contract: this method flushes (so constraint and
        validation failures surface immediately) but never commits;
        durability requires the caller to commit (F11).
        """
        # Complete DB-free contract first: type, filename, extension,
        # size, content type, device id shape, NUL, binary signatures,
        # decode, binary density, empty/whitespace policy.
        content, raw_content, encoding, line_count, content_type = (
            self._validate_and_decode(file_content, filename, content_type,
                                      device_id)
        )

        # Duplicate identity: SHA-256 over the raw bytes (N6 decision).
        content_hash = self._calculate_hash(content)

        # Friendly duplicate pre-check. The UNIQUE index is the
        # authoritative race guard (N5); this only supplies a nicer
        # message with the existing id.
        existing_id = await self._check_duplicates(content_hash)
        if existing_id is not None:
            raise DuplicateConfigurationError(
                f"Configuration with same content already exists "
                f"(ID: {existing_id})",
                configuration_id=existing_id,
                content_hash=content_hash,
            )

        # Device association must reference an existing row so a bad
        # id can never surface as a raw ForeignKeyViolation (N2).
        if device_id is not None and not await self._device_exists(device_id):
            raise InvalidDeviceError(
                f"device_id {device_id} does not identify an existing device"
            )

        config = Configuration(
            id=uuid4(),
            device_id=device_id,
            filename=filename,
            content_hash=content_hash,
            raw_content=raw_content,
            content_type=content_type,
            size_bytes=len(content),
            line_count=line_count,
            encoding=encoding,
            encrypted=False,
        )

        # Savepoint around the insert: under concurrency a UNIQUE or
        # foreign-key violation must roll back only this insert and be
        # translated into a typed error instead of poisoning the
        # caller's transaction (N5/N2).
        try:
            async with self.db.begin_nested():
                self.db.add(config)
                await self.db.flush()
        except IntegrityError as exc:
            raise await self._translate_integrity_error(
                exc, content_hash, device_id
            ) from exc

        return IngestionResult(
            configuration_id=config.id,
            filename=filename,
            content_hash=content_hash,
            size_bytes=len(content),
            line_count=line_count,
            encoding=encoding,
            content=raw_content,
        )

    # ------------------------------------------------------------------
    # Validation pipeline (DB-free)
    # ------------------------------------------------------------------

    def _validate_and_decode(
        self,
        file_content: bytes,
        filename: str,
        content_type: str,
        device_id: Optional[UUID] = None,
    ) -> tuple[bytes, str, str, int, str]:
        """Run the complete database-free ingestion contract.

        Returns (content, decoded_text, encoding, line_count,
        validated_content_type). Raises a typed IngestionError for any
        predictable input problem. This is the single implementation of
        the ingestion rules; ingest() and the dataset sweep both call it.
        """
        content = self._validate_input_type(file_content)
        self._validate_filename(filename)
        self._validate_extension(filename)
        self._validate_size(content)
        validated_content_type = self._validate_content_type(content_type)
        if device_id is not None and not isinstance(device_id, UUID):
            raise InvalidDeviceError(
                f"device_id must be a UUID, got {type(device_id).__name__}"
            )

        # NUL before decode: PostgreSQL TEXT rejects U+0000 and the
        # driver error must never be the thing that notices (F3).
        if b"\x00" in content:
            raise InvalidContentError(
                "configuration content contains NUL bytes"
            )

        # Known binary signatures: content that is unambiguously not
        # configuration text, regardless of how it decodes (F4).
        if self._looks_binary_bytes(content):
            raise InvalidContentError(
                "configuration content starts with a known binary file signature"
            )

        raw_content, encoding = self._decode_content(content)

        # Same non-printable density rule as
        # ValidationEngine._has_binary_content so ingestion and the
        # later validation stage agree on what counts as binary (F4).
        if self._looks_binary_text(raw_content):
            raise InvalidContentError(
                "configuration content contains too many non-printable characters"
            )

        # Empty and whitespace-only content is not a configuration (N8).
        # Comment-only content (leading #, !, //) is non-empty after
        # strip() and remains valid.
        if not raw_content.strip():
            raise InvalidContentError(
                "configuration content is empty or whitespace-only"
            )

        line_count = len(raw_content.splitlines())
        return content, raw_content, encoding, line_count, validated_content_type

    def _validate_input_type(self, file_content: bytes) -> bytes:
        """Enforce the bytes input contract (N4)."""
        if isinstance(file_content, bytearray):
            return bytes(file_content)
        if not isinstance(file_content, bytes):
            raise InvalidContentError(
                "file_content must be bytes or bytearray, "
                f"got {type(file_content).__name__}"
            )
        return file_content

    def _validate_filename(self, filename: str) -> None:
        """Reject unsafe filenames before any persistence (F2/F6/N3).

        Safety rules: printable string only (excludes NUL and all
        control/unicode-format characters), at most MAX_FILENAME_LENGTH
        characters, no path separators or drive letters.
        """
        if not isinstance(filename, str):
            raise InvalidFilenameError(
                f"filename must be a string, got {type(filename).__name__}"
            )
        if not filename:
            raise InvalidFilenameError("filename must not be empty")
        if len(filename) > MAX_FILENAME_LENGTH:
            raise InvalidFilenameError(
                f"filename length {len(filename)} exceeds maximum of "
                f"{MAX_FILENAME_LENGTH} characters"
            )
        if any(not ch.isprintable() for ch in filename):
            raise InvalidFilenameError(
                "filename contains non-printable characters "
                "(control characters, NUL, or unicode format characters)"
            )
        if "/" in filename or "\\" in filename:
            raise InvalidFilenameError(
                "filename must not contain path separators"
            )
        if re.match(r"^[A-Za-z]:", filename):
            raise InvalidFilenameError(
                "filename must not start with a drive letter"
            )

    def _validate_extension(self, filename: str) -> None:
        """Validate file extension is allow-listed"""
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

    def _validate_content_type(self, content_type: str) -> str:
        """Validate the advisory MIME type and return the stored value (F7/N1).

        Empty/None falls back to text/plain. Anything else must be a
        syntactically valid, printable MIME type of at most
        MAX_CONTENT_TYPE_LENGTH characters (the String(50) column
        bound). Mismatched-but-well-formed types are accepted and
        stored verbatim: content and extension stay authoritative.
        """
        if content_type is None or content_type == "":
            return "text/plain"
        if not isinstance(content_type, str):
            raise InvalidContentTypeError(
                "content_type must be a string, "
                f"got {type(content_type).__name__}"
            )
        if len(content_type) > MAX_CONTENT_TYPE_LENGTH:
            raise InvalidContentTypeError(
                f"content_type length {len(content_type)} exceeds maximum "
                f"of {MAX_CONTENT_TYPE_LENGTH} characters"
            )
        if any(not ch.isprintable() for ch in content_type):
            raise InvalidContentTypeError(
                "content_type contains non-printable characters"
            )
        base = content_type.split(";", 1)[0].strip()
        if not _MIME_TYPE_RE.fullmatch(base):
            raise InvalidContentTypeError(
                f"content_type {content_type!r} is not a valid "
                "'type/subtype' MIME value"
            )
        return content_type

    def _calculate_hash(self, content: bytes) -> str:
        """Calculate SHA-256 hash of the raw file bytes"""
        return hashlib.sha256(content).hexdigest()

    async def _check_duplicates(self, content_hash: str) -> Optional[UUID]:
        """Return the id of an existing row with this hash, or None.

        Uses a limited projection so a database corrupted with
        historical duplicate rows can never raise MultipleResultsFound;
        the caller decides how to surface the hit (N5).
        """
        result = await self.db.execute(
            select(Configuration.id)
            .where(Configuration.content_hash == content_hash)
            .limit(1)
        )
        return result.scalars().first()

    async def _device_exists(self, device_id: UUID) -> bool:
        """True when the device row exists (N2)."""
        result = await self.db.execute(
            select(Device.id).where(Device.id == device_id)
        )
        return result.scalars().first() is not None

    async def _translate_integrity_error(
        self,
        exc: IntegrityError,
        content_hash: str,
        device_id: Optional[UUID],
    ) -> IngestionError:
        """Map a race-induced constraint violation to a typed error (N5/N2).

        Runs after the savepoint rolled back the failed insert, so the
        session (and the caller's outer transaction) remains usable.
        """
        orig = getattr(exc, "orig", None)
        sqlstate = str(getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None) or "")
        detail = str(orig if orig is not None else exc).lower()

        if sqlstate == "23505" or "content_hash" in detail:
            winner = await self._check_duplicates(content_hash)
            if winner is not None:
                return DuplicateConfigurationError(
                    f"Configuration with same content already exists "
                    f"(ID: {winner})",
                    configuration_id=winner,
                    content_hash=content_hash,
                )
            return DuplicateConfigurationError(
                "Configuration with same content already exists "
                "(lost a concurrent upload race)",
                configuration_id=None,
                content_hash=content_hash,
            )
        if sqlstate == "23503" or "device_id" in detail or "foreign key" in detail:
            return InvalidDeviceError(
                f"device_id {device_id} violates the configurations "
                "-> devices foreign key"
            )
        return IngestionError("database rejected the configuration")

    # ------------------------------------------------------------------
    # Content inspection helpers
    # ------------------------------------------------------------------

    def _looks_binary_bytes(self, content: bytes) -> bool:
        """True when the raw bytes start with a known binary signature (F4)."""
        if content.startswith(b"MZ") and b"PE\x00\x00" in content[:1024]:
            return True  # Windows executable (bare 'MZ' alone is not enough)
        return any(
            content.startswith(prefix) for prefix in _BINARY_MAGIC_PREFIXES
        )

    def _looks_binary_text(self, text: str) -> bool:
        """Non-printable density check — mirrors ValidationEngine.

        Identical rule to ValidationEngine._has_binary_content (ratio of
        non-printable characters excluding \\n\\r\\t above 10%), so
        ingestion and the later validation stage cannot disagree (F4).
        """
        if not text:
            return False
        non_printable = sum(
            1 for c in text if not c.isprintable() and c not in "\n\r\t"
        )
        return (non_printable / len(text)) > 0.1

    def _decode_content(self, content: bytes) -> tuple[str, str]:
        """Decode configuration bytes with an explicit deterministic strategy.

        1. UTF-8 (strict) — encoding of the entire validation corpus and
           the modern default for configuration exports.
        2. cp-1252 (strict) — Windows-compatible fallback for configs
           exported from legacy terminal tools. Unlike latin-1 it
           rejects its five undefined byte values, which is what makes
           FileDecodeError below reachable instead of dead code (F1).

        Raises FileDecodeError when neither encoding decodes the input;
        arbitrary binary is never silently converted to text.
        """
        try:
            return content.decode("utf-8"), "utf-8"
        except UnicodeDecodeError:
            pass

        try:
            return content.decode("cp1252"), "cp-1252"
        except UnicodeDecodeError:
            pass

        raise FileDecodeError(
            "Unable to decode file content: not valid UTF-8 or cp-1252"
        )
