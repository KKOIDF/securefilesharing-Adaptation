from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File, Header, Form
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse
from starlette.responses import JSONResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo import ReturnDocument
from pymongo.errors import ServerSelectionTimeoutError, AutoReconnect, ConfigurationError
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Literal, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
from passlib.context import CryptContext
import jwt
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
import hashlib
import io
import secrets

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env.local', override=True)
load_dotenv(ROOT_DIR / '.env')

from modules.example_routes import router as example_router
from email_service import send_otp_email
from otp_service import (
    OTP_EXPIRE_MINUTES,
    OTP_MAX_ATTEMPTS,
    OTP_RESEND_COOLDOWN_SECONDS,
    generate_otp,
    get_otp_expiry_time,
    hash_otp,
    is_otp_expired,
    is_resend_allowed,
    verify_otp_hash,
)

class _UnavailableDB:
    def __getattr__(self, name):
        raise HTTPException(
            status_code=503,
            detail="Database unavailable. Start MongoDB or fix MONGO_URL.",
        )


# MongoDB connection
mongo_url = os.environ.get('MONGO_URL')

# Fail fast if MongoDB is not reachable (demo/dev friendly)
MONGO_SERVER_SELECTION_TIMEOUT_MS = int(os.environ.get("MONGO_SERVER_SELECTION_TIMEOUT_MS", "20000"))
MONGO_CONNECT_TIMEOUT_MS = int(os.environ.get("MONGO_CONNECT_TIMEOUT_MS", "20000"))
MONGO_SOCKET_TIMEOUT_MS = int(os.environ.get("MONGO_SOCKET_TIMEOUT_MS", "20000"))

client = None
db = _UnavailableDB()

if mongo_url:
    try:
        client = AsyncIOMotorClient(
            mongo_url,
            serverSelectionTimeoutMS=MONGO_SERVER_SELECTION_TIMEOUT_MS,
            connectTimeoutMS=MONGO_CONNECT_TIMEOUT_MS,
            socketTimeoutMS=MONGO_SOCKET_TIMEOUT_MS,
        )
        db = client[os.environ.get('DB_NAME', 'securefileshare')]
    except (ConfigurationError, Exception):
        logging.getLogger(__name__).exception("Failed to initialize MongoDB client")
        client = None
        db = _UnavailableDB()

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-secret-key-for-development-only')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

app = FastAPI()
api_router = APIRouter(prefix="/api")

logger = logging.getLogger(__name__)


@app.exception_handler(ServerSelectionTimeoutError)
async def mongo_unavailable_handler(request, exc):
    return JSONResponse(
        status_code=503,
        content={
            "detail": "Database unavailable. Start MongoDB on localhost:27017 or set MONGO_URL to a reachable MongoDB instance.",
        },
    )


@app.exception_handler(AutoReconnect)
async def mongo_autoreconnect_handler(request, exc):
    return JSONResponse(
        status_code=503,
        content={
            "detail": "Database connection lost. Ensure MongoDB is running and reachable.",
        },
    )


async def mongo_ping() -> bool:
    if client is None:
        return False
    try:
        await client.admin.command("ping")
        return True
    except Exception:
        return False


async def ensure_indexes() -> None:
    """Create minimal indexes needed for demo features."""
    if client is None:
        return
    try:
        await db.share_links.create_index("token_hash", unique=True)
        await db.share_links.create_index("file_id")
        await db.file_permissions.create_index([("file_id", 1), ("user_email", 1)], unique=True)
        await db.file_access_codes.create_index("code_hash", unique=True)
        await db.file_access_codes.create_index("file_id")
        await db.otp_codes.create_index("email", unique=True)
        await db.otp_codes.create_index("expires_at", expireAfterSeconds=0)
    except Exception:
        # Index creation is best-effort (e.g., restricted MongoDB tiers)
        logger.exception("Failed to ensure MongoDB indexes")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def _b64d(data_b64: str) -> bytes:
    return base64.b64decode(data_b64)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_share_token(token: str) -> str:
    return sha256_hex(token.encode("utf-8"))


def parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value)
        except Exception:
            return None
    return None


def email_map_key(email: str) -> str:
    """Encode an email into a Mongo-safe key.

    We avoid using raw emails as document keys because `.` and `$` can break
    update paths and/or storage rules.
    """
    return base64.urlsafe_b64encode(email.encode("utf-8")).decode("ascii").rstrip("=")

# ========== MODELS ==========

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: str
    role: str = "user"  # "admin" or "user"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str


class OTPResendRequest(BaseModel):
    email: EmailStr


class GoogleAuthRequest(BaseModel):
    id_token: str

class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    email: EmailStr
    full_name: str
    role: str
    password_hash: str
    public_key: str
    private_key: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class FileMetadata(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    original_hash: str
    encrypted_data: str  # Base64 encoded
    encrypted_key: str  # AES key encrypted with RSA
    encryption_mode: str = "cbc"  # "cbc" (legacy) or "gcm"
    encrypted_keys: Dict[str, str] = {}  # map user_email -> RSA-encrypted AES key
    versions: List[Dict[str, Any]] = []  # previous versions (demo)
    owner_id: str
    owner_email: str
    size: int
    shared_with: List[str] = []  # List of user emails
    uploaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Additional discretionary access control (DAC): require a code/password to download
    access_password_hash: Optional[str] = None
    access_password_set_at: Optional[str] = None


class FilePermission(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_id: str
    user_email: EmailStr
    role: Literal["owner", "editor", "viewer"]
    granted_by: EmailStr
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ShareLinkCreateRequest(BaseModel):
    expiresInMinutes: int = Field(gt=0, le=60 * 24 * 30)
    maxUses: int = Field(gt=0, le=1000)
    zeroKnowledge: bool = False
    # Optional: owner can set a custom access code for this link; otherwise system generates one.
    accessCode: Optional[str] = Field(default=None, min_length=4, max_length=128)


class ShareLinkKeySetupRequest(BaseModel):
    encFileKeyB64: str
    ivB64: str
    tagB64: str


class ShareLinkDoc(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_id: str
    token_hash: str
    expires_at: datetime
    max_uses: int
    uses: int = 0
    created_by: EmailStr
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # Optional: if set, client can decrypt the file key using fragment secret
    enc_file_key_b64: Optional[str] = None
    enc_file_key_iv_b64: Optional[str] = None
    enc_file_key_tag_b64: Optional[str] = None
    key_wrap: Literal["token-derived", "fragment-secret"] = "token-derived"
    # Additional secret required to use the link (never store raw code)
    access_code_hash: Optional[str] = None


class FileAccessPasswordRequest(BaseModel):
    password: str = Field(min_length=4, max_length=128)


class FileAccessCodeCreateRequest(BaseModel):
    expiresInMinutes: int = Field(gt=0, le=60 * 24 * 30)
    allowedEmail: Optional[EmailStr] = None
    label: Optional[str] = Field(default=None, max_length=64)
    # Optional: owner can choose a custom code; otherwise system generates one.
    accessCode: Optional[str] = Field(default=None, min_length=4, max_length=128)


class FileAccessCodeDoc(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    file_id: str
    code_hash: str
    expires_at: datetime
    allowed_email: Optional[EmailStr] = None
    label: Optional[str] = None
    created_by: EmailStr
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AccessLog(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_email: str
    action: str
    file_id: Optional[str] = None
    filename: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

# ========== SECURITY UTILITIES ==========

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


async def require_valid_file_access_code(file_doc: dict, current_user: dict, access_code: Optional[str]) -> None:
    """Enforce per-file access code/password before allowing file download.

    Accepts either:
    - the file's access password, or
    - a time-limited access code created by the file owner (optionally bound to a recipient email).
    """
    access_hash = file_doc.get("access_password_hash")
    if not access_hash:
        # For legacy files created before this feature: require owner to set a password first.
        raise HTTPException(status_code=428, detail="File access password is not set. Owner must set one before downloads are allowed.")

    if not access_code:
        raise HTTPException(status_code=401, detail="Access code required")

    # 1) File-level password
    try:
        if verify_password(access_code, access_hash):
            return
    except Exception:
        # Treat as invalid and continue with access-code lookup
        pass

    # 2) Expiring access code
    code_hash = hash_share_token(access_code)
    code_doc = await db.file_access_codes.find_one({"file_id": file_doc.get("id"), "code_hash": code_hash}, {"_id": 0})
    if not code_doc:
        raise HTTPException(status_code=403, detail="Invalid or expired access code")

    expires_at = parse_dt(code_doc.get("expires_at"))
    if expires_at and utc_now() > expires_at:
        raise HTTPException(status_code=403, detail="Invalid or expired access code")

    allowed_email = (code_doc.get("allowed_email") or "").strip().lower() or None
    if allowed_email and allowed_email != (current_user.get("email") or "").strip().lower():
        raise HTTPException(status_code=403, detail="Access code not valid for this user")

    return

def generate_rsa_keypair():
    """Generate RSA key pair for each user"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

def encrypt_file_aes(file_data: bytes) -> tuple[str, str, str]:
    """Encrypt file with AES-256.

    Returns (encrypted_data_b64, aes_key_b64, encryption_mode).

    - gcm: combined format = iv(12) + tag(16) + ciphertext
    - cbc: combined format = iv(16) + ciphertext (legacy)
    """
    # Prefer AES-GCM for authenticated encryption
    aes_key = os.urandom(32)  # 256-bit
    iv = os.urandom(12)  # recommended length for GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_data) + encryptor.finalize()
    tag = encryptor.tag
    combined = iv + tag + ciphertext
    return _b64e(combined), _b64e(aes_key), "gcm"

def _decrypt_file_aes_cbc(encrypted_data_b64: str, aes_key_b64: str) -> bytes:
    combined = _b64d(encrypted_data_b64)
    iv = combined[:16]
    encrypted_data = combined[16:]
    aes_key = _b64d(aes_key_b64)

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    padding_length = padded_data[-1]
    if padding_length < 1 or padding_length > 16:
        raise ValueError("Invalid padding")
    return padded_data[:-padding_length]


def _decrypt_file_aes_gcm(encrypted_data_b64: str, aes_key_b64: str) -> bytes:
    combined = _b64d(encrypted_data_b64)
    iv = combined[:12]
    tag = combined[12:28]
    ciphertext = combined[28:]
    aes_key = _b64d(aes_key_b64)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def decrypt_file_aes(encrypted_data_b64: str, aes_key_b64: str, encryption_mode: Optional[str] = None) -> bytes:
    """Decrypt AES-encrypted file.

    Supports both legacy CBC and new GCM. If mode is missing, attempts GCM then CBC.
    """
    mode = (encryption_mode or "").lower() or None
    if mode == "gcm":
        return _decrypt_file_aes_gcm(encrypted_data_b64, aes_key_b64)
    if mode == "cbc":
        return _decrypt_file_aes_cbc(encrypted_data_b64, aes_key_b64)

    # Auto-detect for backward compatibility
    try:
        return _decrypt_file_aes_gcm(encrypted_data_b64, aes_key_b64)
    except Exception:
        return _decrypt_file_aes_cbc(encrypted_data_b64, aes_key_b64)

def encrypt_key_rsa(aes_key: str, public_key_pem: str) -> str:
    """Encrypt AES key with RSA public key"""
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    encrypted_key = public_key.encrypt(
        base64.b64decode(aes_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(encrypted_key).decode('utf-8')

def decrypt_key_rsa(encrypted_key: str, private_key_pem: str) -> str:
    """Decrypt AES key with RSA private key"""
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    decrypted_key = private_key.decrypt(
        base64.b64decode(encrypted_key),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return base64.b64encode(decrypted_key).decode('utf-8')

def compute_file_hash(file_data: bytes) -> str:
    """Compute SHA-256 hash for file integrity"""
    return hashlib.sha256(file_data).hexdigest()


async def get_file_role(file_doc: dict, current_user: dict) -> Optional[str]:
    if not file_doc:
        return None
    if current_user.get("role") == "admin":
        return "owner"
    if file_doc.get("owner_email") == current_user.get("email"):
        return "owner"

    perm = await db.file_permissions.find_one(
        {"file_id": file_doc.get("id"), "user_email": current_user.get("email")},
        {"_id": 0}
    )
    if perm and perm.get("role"):
        return perm["role"]

    # Legacy fallback
    if current_user.get("email") in file_doc.get("shared_with", []):
        return "viewer"
    return None


async def get_file_key_for_user(file_doc: dict, current_user: dict) -> str:
    """Return AES key (base64) decrypted using current user's private key.

    Supports per-recipient encrypted keys via `encrypted_keys`.
    """
    encrypted_keys = file_doc.get("encrypted_keys") or {}

    user_email = current_user.get("email") or ""
    encrypted_key = encrypted_keys.get(user_email)
    if not encrypted_key:
        encrypted_key = encrypted_keys.get(email_map_key(user_email))

    # Backward-compat: earlier buggy writes used dot-path updates which can
    # produce nested dicts based on '.' splitting.
    if not encrypted_key and isinstance(encrypted_keys, dict) and user_email and "." in user_email:
        node: Any = encrypted_keys
        try:
            for part in user_email.split("."):
                if not isinstance(node, dict):
                    node = None
                    break
                node = node.get(part)
            if isinstance(node, str):
                encrypted_key = node
        except Exception:
            pass
    if not encrypted_key:
        # fallback to legacy owner-only encrypted_key
        encrypted_key = file_doc.get("encrypted_key")
    if not encrypted_key:
        raise HTTPException(status_code=500, detail="Missing encrypted key")
    return decrypt_key_rsa(encrypted_key, current_user["private_key"])


async def build_encrypted_keys_for_file(file_id: str, owner_email: str, owner_key_b64: str) -> Dict[str, str]:
    """Build encrypted_keys map for all users with permissions (including owner)."""
    encrypted_keys: Dict[str, str] = {}

    # Owner
    owner_user = await db.users.find_one({"email": owner_email}, {"_id": 0})
    if not owner_user:
        raise HTTPException(status_code=500, detail="Owner record missing")
    encrypted_keys[email_map_key(owner_email)] = encrypt_key_rsa(owner_key_b64, owner_user["public_key"])

    # Shared users (viewer/editor)
    perms = await db.file_permissions.find({"file_id": file_id}, {"_id": 0, "user_email": 1, "role": 1}).to_list(5000)
    for p in perms:
        email = p.get("user_email")
        role = p.get("role")
        if not email or email == owner_email:
            continue
        if role not in ("viewer", "editor"):
            continue
        user = await db.users.find_one({"email": email}, {"_id": 0, "public_key": 1})
        if user and user.get("public_key"):
            encrypted_keys[email_map_key(email)] = encrypt_key_rsa(owner_key_b64, user["public_key"])

    return encrypted_keys


def require_role(role: Optional[str], allowed: List[str]):
    if role not in allowed:
        raise HTTPException(status_code=403, detail="Access denied")


def _frontend_base_url() -> str:
    explicit = os.environ.get("FRONTEND_BASE_URL")
    if explicit:
        return explicit.rstrip("/")
    cors = os.environ.get("CORS_ORIGINS", "").split(",")
    if cors and cors[0].strip():
        return cors[0].strip().rstrip("/")
    return "http://localhost:3000"


def _wrap_file_key_token_derived(file_key_b64: str, token: str) -> dict:
    """Encrypt the file AES key for delivery over an unauthenticated share link.

    Uses AES-GCM with a key derived from SHA-256(token). The server does not store the token.
    """
    derived_key = hashlib.sha256(token.encode("utf-8")).digest()  # 32 bytes
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(derived_key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    plaintext_key = _b64d(file_key_b64)
    ciphertext = encryptor.update(plaintext_key) + encryptor.finalize()
    tag = encryptor.tag
    return {
        "ciphertextB64": _b64e(ciphertext),
        "ivB64": _b64e(iv),
        "tagB64": _b64e(tag),
        "wrap": "token-derived",
    }

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

async def log_action(user_email: str, action: str, file_id: str = None, filename: str = None):
    log_entry = AccessLog(
        user_email=user_email,
        action=action,
        file_id=file_id,
        filename=filename
    )
    doc = log_entry.model_dump()
    doc['timestamp'] = doc['timestamp'].isoformat()
    await db.access_logs.insert_one(doc)

# ========== AUTH ENDPOINTS ==========

@api_router.post("/auth/register")
async def register(user_data: UserRegister):
    # Check if user exists
    existing = await db.users.find_one({"email": user_data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Generate RSA keys
    private_key, public_key = generate_rsa_keypair()
    
    # Create user
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role,
        password_hash=hash_password(user_data.password),
        public_key=public_key,
        private_key=private_key
    )
    
    doc = user.model_dump()
    doc['created_at'] = doc['created_at'].isoformat()
    await db.users.insert_one(doc)
    
    await log_action(user.email, "User registered")
    
    return {"message": "User registered successfully", "email": user.email, "role": user.role}

@api_router.post("/auth/login")
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    otp = generate_otp()

    await db.otp_codes.replace_one({"email": credentials.email}, {
        "email": credentials.email,
        "otp_hash": hash_otp(otp),
        "attempts": 0,
        "created_at": datetime.now(timezone.utc),
        "expires_at": get_otp_expiry_time(),
    }, upsert=True)

    try:
        await run_in_threadpool(send_otp_email, credentials.email, otp, OTP_EXPIRE_MINUTES)
    except Exception:
        await db.otp_codes.delete_many({"email": credentials.email})
        logger.exception("Failed to send OTP email to %s", credentials.email)
        raise HTTPException(status_code=503, detail="Unable to send OTP email. Please try again later.")
    
    await log_action(user["email"], "Login attempt - OTP sent")
    
    return {
        "message": "OTP sent to your email",
        "email": credentials.email,
        "expires_in_minutes": OTP_EXPIRE_MINUTES,
        "resend_cooldown_seconds": OTP_RESEND_COOLDOWN_SECONDS,
    }

@api_router.post("/auth/verify-otp")
async def verify_otp(verification: OTPVerify):
    otp_record = await db.otp_codes.find_one({"email": verification.email})
    
    if not otp_record:
        raise HTTPException(status_code=400, detail="No OTP found. Please login again.")
    
    if is_otp_expired(otp_record["expires_at"]):
        await db.otp_codes.delete_many({"email": verification.email})
        raise HTTPException(status_code=400, detail="OTP expired. Please login again.")

    if otp_record.get("attempts", 0) >= OTP_MAX_ATTEMPTS:
        await db.otp_codes.delete_many({"email": verification.email})
        raise HTTPException(status_code=400, detail="Too many OTP attempts. Please login again.")

    if not verify_otp_hash(verification.otp, otp_record["otp_hash"]):
        updated = await db.otp_codes.find_one_and_update(
            {"email": verification.email},
            {"$inc": {"attempts": 1}},
            return_document=ReturnDocument.AFTER,
        )
        if updated and updated.get("attempts", 0) >= OTP_MAX_ATTEMPTS:
            await db.otp_codes.delete_many({"email": verification.email})
            raise HTTPException(status_code=400, detail="Too many OTP attempts. Please login again.")
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    await db.otp_codes.delete_many({"email": verification.email})
    
    user = await db.users.find_one({"email": verification.email}, {"_id": 0})
    
    token = create_access_token({"sub": user["email"], "role": user["role"]})
    
    await log_action(user["email"], "Login successful")
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": user["email"],
            "full_name": user["full_name"],
            "role": user["role"]
        }
    }

@api_router.post("/auth/resend-otp")
async def resend_otp(data: OTPResendRequest):
    email = data.email
    user = await db.users.find_one({"email": email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    existing_otp = await db.otp_codes.find_one({"email": email})
    if not existing_otp:
        raise HTTPException(status_code=400, detail="No OTP found. Please login again.")

    if is_otp_expired(existing_otp["expires_at"]):
        await db.otp_codes.delete_many({"email": email})
        raise HTTPException(status_code=400, detail="OTP expired. Please login again.")

    if not is_resend_allowed(existing_otp["created_at"]):
        raise HTTPException(
            status_code=429,
            detail=f"Please wait {OTP_RESEND_COOLDOWN_SECONDS} seconds before requesting another OTP.",
        )

    otp = generate_otp()

    await db.otp_codes.replace_one({"email": email}, {
        "email": email,
        "otp_hash": hash_otp(otp),
        "attempts": 0,
        "created_at": datetime.now(timezone.utc),
        "expires_at": get_otp_expiry_time(),
    }, upsert=True)

    try:
        await run_in_threadpool(send_otp_email, email, otp, OTP_EXPIRE_MINUTES)
    except Exception:
        await db.otp_codes.delete_many({"email": email})
        logger.exception("Failed to resend OTP email to %s", email)
        raise HTTPException(status_code=503, detail="Unable to send OTP email. Please try again later.")

    await log_action(user["email"], "OTP resent")

    return {
        "message": "New OTP sent to your email",
        "expires_in_minutes": OTP_EXPIRE_MINUTES,
        "resend_cooldown_seconds": OTP_RESEND_COOLDOWN_SECONDS,
    }


@api_router.post("/auth/google")
async def google_login(payload: GoogleAuthRequest):
    google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
    if not google_client_id:
        raise HTTPException(status_code=500, detail="GOOGLE_CLIENT_ID is not configured on the server")

    try:
        idinfo = google_id_token.verify_oauth2_token(
            payload.id_token,
            google_requests.Request(),
            audience=google_client_id,
        )
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid Google token")

    email = (idinfo.get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=400, detail="Google token missing email")

    if idinfo.get("email_verified") is False:
        raise HTTPException(status_code=401, detail="Google email is not verified")

    full_name = (idinfo.get("name") or idinfo.get("given_name") or "").strip() or email.split("@")[0]

    try:
        user = await db.users.find_one({"email": email}, {"_id": 0})
        if not user:
            private_key, public_key = generate_rsa_keypair()
            random_password = secrets.token_urlsafe(32)
            new_user = User(
                email=email,
                full_name=full_name,
                role="user",
                password_hash=hash_password(random_password),
                public_key=public_key,
                private_key=private_key,
            )
            doc = new_user.model_dump()
            doc["created_at"] = doc["created_at"].isoformat()
            doc["auth_provider"] = "google"
            doc["google_sub"] = idinfo.get("sub")
            await db.users.insert_one(doc)
            user = doc
            await log_action(email, "Google login - user created")
        else:
            await log_action(email, "Google login")
    except Exception:
        logger.exception("Google login failed due to database error")
        raise HTTPException(status_code=503, detail="Database unavailable")

    token = create_access_token({"sub": user["email"], "role": user.get("role", "user")})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "email": user["email"],
            "full_name": user.get("full_name") or full_name,
            "role": user.get("role", "user"),
        },
    }

# ========== FILE ENDPOINTS ==========

@api_router.post("/files/upload")
async def upload_file(
    file: UploadFile = File(...),
    access_password: str = Form(...),
    current_user: dict = Depends(get_current_user)
):
    # Read file
    file_data = await file.read()
    
    # Compute hash for integrity
    file_hash = compute_file_hash(file_data)
    
    # Encrypt file with AES-256
    encrypted_data, aes_key, encryption_mode = encrypt_file_aes(file_data)
    
    # Encrypt AES key with user's RSA public key
    encrypted_key = encrypt_key_rsa(aes_key, current_user["public_key"])
    
    # Store in database
    file_metadata = FileMetadata(
        filename=file.filename,
        original_hash=file_hash,
        encrypted_data=encrypted_data,
        encrypted_key=encrypted_key,
        encryption_mode=encryption_mode,
        encrypted_keys={email_map_key(current_user["email"]): encrypted_key},
        owner_id=current_user["id"],
        owner_email=current_user["email"],
        size=len(file_data),
        access_password_hash=hash_password(access_password),
        access_password_set_at=utc_now().isoformat(),
    )
    
    doc = file_metadata.model_dump()
    doc['uploaded_at'] = doc['uploaded_at'].isoformat()
    await db.files.insert_one(doc)

    # Ensure owner permission exists
    owner_perm = FilePermission(
        file_id=file_metadata.id,
        user_email=current_user["email"],
        role="owner",
        granted_by=current_user["email"],
    ).model_dump()
    owner_perm["created_at"] = owner_perm["created_at"].isoformat()
    await db.file_permissions.update_one(
        {"file_id": file_metadata.id, "user_email": current_user["email"]},
        {"$setOnInsert": owner_perm},
        upsert=True,
    )
    
    await log_action(current_user["email"], "File uploaded", file_metadata.id, file.filename)
    
    return {
        "message": "File uploaded and encrypted successfully",
        "file_id": file_metadata.id,
        "filename": file.filename,
        "hash": file_hash
    }

@api_router.get("/files/list")
async def list_files(current_user: dict = Depends(get_current_user)):
    # Get files owned by user or accessible via file_permissions (RBAC) or legacy shared_with
    permitted_file_ids = await db.file_permissions.find(
        {"user_email": current_user["email"]},
        {"_id": 0, "file_id": 1}
    ).to_list(5000)
    permitted_ids = [p["file_id"] for p in permitted_file_ids if p.get("file_id")]

    query = {
        "$or": [
            {"owner_email": current_user["email"]},
            {"id": {"$in": permitted_ids}} if permitted_ids else {"id": "__none__"},
            {"shared_with": current_user["email"]},
        ]
    }
    files = await db.files.find(
        query,
        {"_id": 0, "encrypted_data": 0, "encrypted_key": 0, "access_password_hash": 0},
    ).to_list(1000)

    # Attach caller's role for UI decisions
    for f in files:
        f["my_role"] = await get_file_role(f, current_user)
        f["access_protected"] = bool(f.get("access_password_hash"))
    
    return {"files": files}

@api_router.get("/files/download/{file_id}")
async def download_file(
    file_id: str,
    x_file_access_code: Optional[str] = Header(None, alias="X-File-Access-Code"),
    current_user: dict = Depends(get_current_user),
):
    # Get file
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    role = await get_file_role(file_doc, current_user)
    require_role(role, ["viewer", "editor", "owner"])

    # Enforce access password/code for everyone (including owner)
    await require_valid_file_access_code(file_doc, current_user, x_file_access_code)
    
    # Decrypt AES key with user's RSA private key (supports per-recipient keys)
    aes_key = await get_file_key_for_user(file_doc, current_user)
    
    # Decrypt file
    decrypted_data = decrypt_file_aes(file_doc["encrypted_data"], aes_key, file_doc.get("encryption_mode"))
    
    # Verify integrity
    current_hash = compute_file_hash(decrypted_data)
    if current_hash != file_doc["original_hash"]:
        raise HTTPException(status_code=500, detail="File integrity check failed")
    
    await log_action(current_user["email"], "File downloaded", file_id, file_doc["filename"])
    
    return StreamingResponse(
        io.BytesIO(decrypted_data),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f"attachment; filename={file_doc['filename']}"}
    )


@api_router.put("/files/{file_id}/access-password")
async def set_file_access_password(
    file_id: str,
    body: FileAccessPasswordRequest,
    current_user: dict = Depends(get_current_user),
):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])

    await db.files.update_one(
        {"id": file_id},
        {"$set": {"access_password_hash": hash_password(body.password), "access_password_set_at": utc_now().isoformat()}},
    )
    await log_action(current_user["email"], "SET_ACCESS_PASSWORD", file_id, file_doc.get("filename"))
    return {"message": "Access password set"}


@api_router.delete("/files/{file_id}/access-password")
async def clear_file_access_password(
    file_id: str,
    current_user: dict = Depends(get_current_user),
):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])

    await db.files.update_one({"id": file_id}, {"$set": {"access_password_hash": None, "access_password_set_at": None}})
    await db.file_access_codes.delete_many({"file_id": file_id})
    await log_action(current_user["email"], "CLEAR_ACCESS_PASSWORD", file_id, file_doc.get("filename"))
    return {"message": "Access password cleared"}


@api_router.post("/files/{file_id}/access-codes")
async def create_file_access_code(
    file_id: str,
    body: FileAccessCodeCreateRequest,
    current_user: dict = Depends(get_current_user),
):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])

    # Ensure the file has a password configured (baseline protection)
    if not file_doc.get("access_password_hash"):
        raise HTTPException(status_code=428, detail="File access password is not set. Set it before creating access codes.")

    # DAC convenience: if the code is bound to an email, also grant viewer access and prepare the per-recipient file key.
    if body.allowedEmail:
        recipient_email = body.allowedEmail.strip().lower()
        target_user = await db.users.find_one({"email": recipient_email}, {"_id": 0})
        if not target_user:
            raise HTTPException(status_code=404, detail="Target user not found")

        try:
            owner_file_key_b64 = await get_file_key_for_user(file_doc, current_user)
            recipient_encrypted_key = encrypt_key_rsa(owner_file_key_b64, target_user["public_key"])
            safe_recipient_key = email_map_key(recipient_email)
            await db.files.update_one(
                {"id": file_id},
                {"$set": {f"encrypted_keys.{safe_recipient_key}": recipient_encrypted_key}},
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to prepare key for recipient: {str(e)}")

        # Add to shared list (legacy UI field)
        if recipient_email not in file_doc.get("shared_with", []):
            await db.files.update_one({"id": file_id}, {"$addToSet": {"shared_with": recipient_email}})

        # Upsert RBAC permission (viewer)
        perm_doc = FilePermission(
            file_id=file_id,
            user_email=recipient_email,
            role="viewer",
            granted_by=current_user["email"],
        ).model_dump()
        perm_doc["created_at"] = perm_doc["created_at"].isoformat()
        perm_doc_on_insert = {
            "id": perm_doc["id"],
            "file_id": perm_doc["file_id"],
            "user_email": perm_doc["user_email"],
            "created_at": perm_doc["created_at"],
        }
        await db.file_permissions.update_one(
            {"file_id": file_id, "user_email": recipient_email},
            {"$set": {"role": "viewer", "granted_by": current_user["email"]}, "$setOnInsert": perm_doc_on_insert},
            upsert=True,
        )

    raw_code = (body.accessCode or "").strip() or secrets.token_urlsafe(12)
    code_hash = hash_share_token(raw_code)
    expires_at = utc_now() + timedelta(minutes=body.expiresInMinutes)

    doc = FileAccessCodeDoc(
        file_id=file_id,
        code_hash=code_hash,
        expires_at=expires_at,
        allowed_email=(body.allowedEmail.strip().lower() if body.allowedEmail else None),
        label=(body.label.strip() if body.label else None),
        created_by=current_user["email"],
    ).model_dump()
    doc["created_at"] = doc["created_at"].isoformat()
    doc["expires_at"] = doc["expires_at"].isoformat()

    await db.file_access_codes.insert_one(doc)
    await log_action(current_user["email"], "CREATE_ACCESS_CODE", file_id, file_doc.get("filename"))

    return {
        "id": doc["id"],
        "code": raw_code,
        "expires_at": doc["expires_at"],
        "allowed_email": doc.get("allowed_email"),
        "label": doc.get("label"),
    }


@api_router.get("/files/{file_id}/access-codes")
async def list_file_access_codes(
    file_id: str,
    current_user: dict = Depends(get_current_user),
):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])

    codes = await db.file_access_codes.find({"file_id": file_id}, {"_id": 0, "code_hash": 0}).sort("created_at", -1).to_list(200)
    return {"codes": codes}


@api_router.delete("/files/{file_id}/access-codes/{code_id}")
async def revoke_file_access_code(
    file_id: str,
    code_id: str,
    current_user: dict = Depends(get_current_user),
):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])

    await db.file_access_codes.delete_one({"id": code_id, "file_id": file_id})
    await log_action(current_user["email"], "REVOKE_ACCESS_CODE", file_id, file_doc.get("filename"))
    return {"message": "Access code revoked"}

@api_router.delete("/files/delete/{file_id}")
async def delete_file(file_id: str, current_user: dict = Depends(get_current_user)):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    # Only owner or admin can delete
    if file_doc["owner_email"] != current_user["email"] and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Access denied")
    
    await db.files.delete_one({"id": file_id})
    await db.file_permissions.delete_many({"file_id": file_id})
    await db.share_links.delete_many({"file_id": file_id})
    await log_action(current_user["email"], "File deleted", file_id, file_doc["filename"])
    
    return {"message": "File deleted successfully"}

@api_router.post("/files/share/{file_id}")
async def share_file(
    file_id: str,
    data: dict,
    current_user: dict = Depends(get_current_user)
):
    share_with_email = data.get("email")
    share_role = (data.get("role") or "viewer").lower()
    if share_role not in ("viewer", "editor"):
        raise HTTPException(status_code=400, detail="Invalid role")
    
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")
    
    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])
    
    # Check if target user exists
    target_user = await db.users.find_one({"email": share_with_email}, {"_id": 0})
    if not target_user:
        raise HTTPException(status_code=404, detail="Target user not found")

    # Re-encrypt file AES key for recipient so they can actually download
    try:
        owner_file_key_b64 = await get_file_key_for_user(file_doc, current_user)
        recipient_encrypted_key = encrypt_key_rsa(owner_file_key_b64, target_user["public_key"])
        safe_recipient_key = email_map_key(share_with_email)
        await db.files.update_one(
            {"id": file_id},
            {"$set": {f"encrypted_keys.{safe_recipient_key}": recipient_encrypted_key}}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to prepare key for recipient: {str(e)}")
    
    # Add to shared list
    if share_with_email not in file_doc.get("shared_with", []):
        await db.files.update_one(
            {"id": file_id},
            {"$push": {"shared_with": share_with_email}}
        )

    # Upsert RBAC permission
    perm_doc = FilePermission(
        file_id=file_id,
        user_email=share_with_email,
        role=share_role,
        granted_by=current_user["email"],
    ).model_dump()
    perm_doc["created_at"] = perm_doc["created_at"].isoformat()

    # Avoid MongoDB update conflicts: do not include fields in both $set and $setOnInsert
    perm_doc_on_insert = {
        "id": perm_doc["id"],
        "file_id": perm_doc["file_id"],
        "user_email": perm_doc["user_email"],
        "created_at": perm_doc["created_at"],
    }
    await db.file_permissions.update_one(
        {"file_id": file_id, "user_email": share_with_email},
        {"$set": {"role": share_role, "granted_by": current_user["email"]}, "$setOnInsert": perm_doc_on_insert},
        upsert=True,
    )
    
    await log_action(current_user["email"], f"File shared with {share_with_email}", file_id, file_doc["filename"])
    
    return {"message": f"File shared with {share_with_email}"}


@api_router.patch("/files/rename/{file_id}")
async def rename_file(file_id: str, data: dict, current_user: dict = Depends(get_current_user)):
    new_name = (data.get("filename") or "").strip()
    if not new_name:
        raise HTTPException(status_code=400, detail="filename is required")

    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["editor", "owner"])

    await db.files.update_one({"id": file_id}, {"$set": {"filename": new_name}})
    await log_action(current_user["email"], "File renamed", file_id, new_name)
    return {"message": "File renamed", "filename": new_name}


@api_router.post("/files/upload-version/{file_id}")
async def upload_new_version(
    file_id: str,
    file: UploadFile = File(...),
    current_user: dict = Depends(get_current_user),
):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["editor", "owner"])

    file_data = await file.read()
    file_hash = compute_file_hash(file_data)
    encrypted_data, aes_key, encryption_mode = encrypt_file_aes(file_data)

    # Owner key and per-recipient key map for this new version
    owner_email = file_doc["owner_email"]
    owner_user = await db.users.find_one({"email": owner_email}, {"_id": 0})
    if not owner_user:
        raise HTTPException(status_code=500, detail="Owner record missing")

    encrypted_key_owner = encrypt_key_rsa(aes_key, owner_user["public_key"])
    encrypted_keys = await build_encrypted_keys_for_file(file_id, owner_email, aes_key)
    encrypted_keys[email_map_key(owner_email)] = encrypted_key_owner

    prev_snapshot = {
        "filename": file_doc.get("filename"),
        "original_hash": file_doc.get("original_hash"),
        "encrypted_data": file_doc.get("encrypted_data"),
        "encrypted_key": file_doc.get("encrypted_key"),
        "encryption_mode": file_doc.get("encryption_mode"),
        "encrypted_keys": file_doc.get("encrypted_keys"),
        "size": file_doc.get("size"),
        "uploaded_at": file_doc.get("uploaded_at"),
    }

    await db.files.update_one(
        {"id": file_id},
        {
            "$push": {"versions": prev_snapshot},
            "$set": {
                "filename": file.filename or file_doc.get("filename"),
                "original_hash": file_hash,
                "encrypted_data": encrypted_data,
                "encrypted_key": encrypted_key_owner,
                "encryption_mode": encryption_mode,
                "encrypted_keys": encrypted_keys,
                "size": len(file_data),
                "uploaded_at": utc_now().isoformat(),
            },
        },
    )

    await log_action(current_user["email"], "File version uploaded", file_id, file.filename)
    return {"message": "New version uploaded", "file_id": file_id, "filename": file.filename, "hash": file_hash}


@api_router.delete("/files/revoke/{file_id}")
async def revoke_file_access(
    file_id: str,
    data: dict,
    current_user: dict = Depends(get_current_user)
):
    target_email = data.get("email")
    if not target_email:
        raise HTTPException(status_code=400, detail="Email is required")

    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])

    await db.file_permissions.delete_one({"file_id": file_id, "user_email": target_email})
    await db.files.update_one({"id": file_id}, {"$pull": {"shared_with": target_email}})
    await log_action(current_user["email"], "REVOKE_ACCESS", file_id, file_doc.get("filename"))
    return {"message": f"Access revoked for {target_email}"}


@api_router.get("/files/key/{file_id}")
async def export_file_key(file_id: str, current_user: dict = Depends(get_current_user)):
    """Export the raw file AES key to the owner.

    This is intended for demo/zero-knowledge link setup where the client encrypts
    the file key with a link secret (never sent to the server).
    """
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])

    aes_key_b64 = await get_file_key_for_user(file_doc, current_user)
    return {"file_id": file_id, "aes_key_b64": aes_key_b64, "encryption_mode": file_doc.get("encryption_mode", "cbc")}


@api_router.post("/files/{file_id}/share-link")
async def create_share_link(
    file_id: str,
    body: ShareLinkCreateRequest,
    current_user: dict = Depends(get_current_user)
):
    file_doc = await db.files.find_one({"id": file_id}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])

    token = secrets.token_urlsafe(32)
    token_hash = hash_share_token(token)
    expires_at = utc_now() + timedelta(minutes=body.expiresInMinutes)

    raw_access_code = (body.accessCode or "").strip() or secrets.token_urlsafe(12)
    access_code_hash = hash_share_token(raw_access_code)

    link = ShareLinkDoc(
        file_id=file_id,
        token_hash=token_hash,
        expires_at=expires_at,
        max_uses=body.maxUses,
        uses=0,
        created_by=current_user["email"],
        key_wrap="fragment-secret" if body.zeroKnowledge else "token-derived",
        access_code_hash=access_code_hash,
    )
    doc = link.model_dump()
    doc["created_at"] = doc["created_at"].isoformat()
    doc["expires_at"] = doc["expires_at"].isoformat()
    await db.share_links.insert_one(doc)

    await log_action(current_user["email"], "CREATE_LINK", file_id, file_doc.get("filename"))

    url = f"{_frontend_base_url()}/share/{token}"
    # Return accessCode once so owner can share it out-of-band.
    return {"url": url, "zeroKnowledge": body.zeroKnowledge, "accessCode": raw_access_code}


@api_router.post("/share/{token}/zk-setup")
async def setup_zero_knowledge_link(
    token: str,
    body: ShareLinkKeySetupRequest,
    current_user: dict = Depends(get_current_user)
):
    token_hash = hash_share_token(token)
    link_doc = await db.share_links.find_one({"token_hash": token_hash}, {"_id": 0})
    if not link_doc:
        raise HTTPException(status_code=404, detail="Share link not found")

    file_doc = await db.files.find_one({"id": link_doc["file_id"]}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    role = await get_file_role(file_doc, current_user)
    require_role(role, ["owner"])

    await db.share_links.update_one(
        {"token_hash": token_hash},
        {
            "$set": {
                "enc_file_key_b64": body.encFileKeyB64,
                "enc_file_key_iv_b64": body.ivB64,
                "enc_file_key_tag_b64": body.tagB64,
                "key_wrap": "fragment-secret",
            }
        },
    )

    return {"message": "Zero-knowledge key setup saved"}


@api_router.get("/share/{token}")
async def get_share_link_payload(
    token: str,
    x_share_access_code: Optional[str] = Header(None, alias="X-Share-Access-Code"),
):
    token_hash = hash_share_token(token)
    now_iso = utc_now().isoformat()

    # Read first, then consume only after payload is successfully prepared.
    # This avoids consuming a token if the file is missing or server fails
    # while building the payload.
    link_doc = await db.share_links.find_one({"token_hash": token_hash}, {"_id": 0})
    if not link_doc:
        raise HTTPException(status_code=404, detail="Share link not found")

    try:
        expires_at = datetime.fromisoformat(link_doc["expires_at"]) if isinstance(link_doc.get("expires_at"), str) else None
    except Exception:
        expires_at = None

    if expires_at and utc_now() > expires_at:
        raise HTTPException(status_code=410, detail="Link expired")
    if int(link_doc.get("uses", 0)) >= int(link_doc.get("max_uses", 0) or 0):
        raise HTTPException(status_code=410, detail="Link consumed")

    file_doc = await db.files.find_one({"id": link_doc["file_id"]}, {"_id": 0})
    if not file_doc:
        raise HTTPException(status_code=404, detail="File not found")

    # Require a password/code to use the link.
    if not x_share_access_code:
        raise HTTPException(status_code=401, detail="Access code required")

    # Accept either the per-file password or the link-specific access code.
    ok = False
    try:
        file_pw_hash = file_doc.get("access_password_hash")
        if file_pw_hash and verify_password(x_share_access_code, file_pw_hash):
            ok = True
    except Exception:
        ok = False

    if not ok:
        link_code_hash = link_doc.get("access_code_hash")
        if link_code_hash and hash_share_token(x_share_access_code) == link_code_hash:
            ok = True

    if not ok:
        raise HTTPException(status_code=403, detail="Invalid or expired access code")

    # Split encrypted file payload for client-side decrypt
    combined = _b64d(file_doc["encrypted_data"])
    enc_mode = (file_doc.get("encryption_mode") or "cbc").lower()
    if enc_mode == "gcm":
        file_iv = combined[:12]
        file_tag = combined[12:28]
        file_ciphertext = combined[28:]
        file_tag_b64 = _b64e(file_tag)
    else:
        file_iv = combined[:16]
        file_ciphertext = combined[16:]
        file_tag_b64 = ""

    # Provide wrapped file key
    if link_doc.get("enc_file_key_b64") and link_doc.get("enc_file_key_iv_b64") and link_doc.get("enc_file_key_tag_b64"):
        wrapped_key = {
            "ciphertextB64": link_doc["enc_file_key_b64"],
            "ivB64": link_doc["enc_file_key_iv_b64"],
            "tagB64": link_doc["enc_file_key_tag_b64"],
            "wrap": "fragment-secret",
        }
    else:
        # Decrypt AES key using owner's private key and wrap with token-derived key
        owner = await db.users.find_one({"email": file_doc["owner_email"]}, {"_id": 0})
        if not owner:
            raise HTTPException(status_code=500, detail="Owner record missing")
        file_key_b64 = decrypt_key_rsa(file_doc["encrypted_key"], owner["private_key"])
        wrapped_key = _wrap_file_key_token_derived(file_key_b64, token)

    # Atomically consume a use now that payload is ready.
    consumed = await db.share_links.find_one_and_update(
        {
            "token_hash": token_hash,
            "expires_at": {"$gt": now_iso},
            "$expr": {"$lt": ["$uses", "$max_uses"]},
        },
        {"$inc": {"uses": 1}},
        projection={"_id": 0, "uses": 1, "max_uses": 1, "expires_at": 1},
        return_document=ReturnDocument.AFTER,
    )
    if not consumed:
        # distinguish expired vs consumed if possible
        existing = await db.share_links.find_one(
            {"token_hash": token_hash},
            {"_id": 0, "expires_at": 1, "uses": 1, "max_uses": 1},
        )
        if not existing:
            raise HTTPException(status_code=404, detail="Share link not found")
        try:
            if utc_now() > datetime.fromisoformat(existing["expires_at"]):
                raise HTTPException(status_code=410, detail="Link expired")
        except Exception:
            pass
        raise HTTPException(status_code=410, detail="Link consumed")

    await log_action("anonymous", "CONSUME_LINK", file_doc.get("id"), file_doc.get("filename"))

    return {
        "file": {
            "id": file_doc.get("id"),
            "filename": file_doc.get("filename"),
            "size": file_doc.get("size"),
        },
        "integrity": {
            "sha256": file_doc.get("original_hash"),
        },
        "encryption": {
            "mode": enc_mode,
            "ciphertextB64": _b64e(file_ciphertext),
            "ivB64": _b64e(file_iv),
            "tagB64": file_tag_b64,
        },
        "encryptedFileKey": wrapped_key,
    }

# ========== ADMIN ENDPOINTS ==========

@api_router.get("/admin/users")
async def get_all_users(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    users = await db.users.find(
        {},
        {"_id": 0, "password_hash": 0, "private_key": 0, "public_key": 0}
    ).to_list(1000)
    
    return {"users": users}

@api_router.get("/admin/logs")
async def get_access_logs(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    logs = await db.access_logs.find({}, {"_id": 0}).sort("timestamp", -1).to_list(1000)
    
    return {"logs": logs}

@api_router.get("/admin/stats")
async def get_stats(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    total_users = await db.users.count_documents({})
    total_files = await db.files.count_documents({})
    total_logs = await db.access_logs.count_documents({})
    
    return {
        "total_users": total_users,
        "total_files": total_files,
        "total_logs": total_logs
    }

# ========== ROOT ==========

@api_router.get("/")
async def root():
    return {"message": "SecureShare API - File Sharing with AES-256 & RSA Encryption"}


@api_router.get("/health/db")
async def health_db():
    ok = await mongo_ping()
    return {"db": "ok" if ok else "down"}

# Include routers
app.include_router(api_router)
app.include_router(example_router, prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

@app.on_event("shutdown")
async def shutdown_db_client():
    if client is not None:
        client.close()


@app.on_event("startup")
async def startup_indexes():
    await ensure_indexes()
