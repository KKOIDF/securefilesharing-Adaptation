import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone


OTP_EXPIRE_MINUTES = int(os.getenv("OTP_EXPIRE_MINUTES", "5"))
OTP_RESEND_COOLDOWN_SECONDS = int(os.getenv("OTP_RESEND_COOLDOWN_SECONDS", "60"))
OTP_MAX_ATTEMPTS = int(os.getenv("OTP_MAX_ATTEMPTS", "5"))


def generate_otp() -> str:
    return f"{secrets.randbelow(900000) + 100000:06d}"


def hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode("utf-8")).hexdigest()


def verify_otp_hash(otp: str, otp_hash: str) -> bool:
    return hmac.compare_digest(hash_otp(otp), otp_hash)


def get_otp_expiry_time() -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)


def normalize_utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def is_otp_expired(expires_at: datetime) -> bool:
    return datetime.now(timezone.utc) > normalize_utc_datetime(expires_at)


def is_resend_allowed(created_at: datetime) -> bool:
    cooldown = timedelta(seconds=OTP_RESEND_COOLDOWN_SECONDS)
    return datetime.now(timezone.utc) >= normalize_utc_datetime(created_at) + cooldown
