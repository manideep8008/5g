import hashlib
import hmac
import os

_HMAC_KEY: bytes | None = None


def _get_hmac_key() -> bytes:
    global _HMAC_KEY
    if _HMAC_KEY is None:
        key_hex = os.environ.get("HMAC_SECRET_KEY", "default_dev_key_not_for_production")
        _HMAC_KEY = key_hex.encode("utf-8")
    return _HMAC_KEY


def pseudonymise_imsi(imsi: str) -> str:
    digest = hmac.new(_HMAC_KEY or _get_hmac_key(), imsi.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"UE_HASH_{digest[:12].upper()}"


def verify_pseudonym(imsi: str, pseudonym: str) -> bool:
    return pseudonymise_imsi(imsi) == pseudonym
