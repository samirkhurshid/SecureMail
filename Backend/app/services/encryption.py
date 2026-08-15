"""
Symmetric field-level encryption using Fernet.
Used to encrypt sensitive identifying metadata at rest (client IP, User-Agent).
"""

from typing import Optional
from cryptography.fernet import Fernet, InvalidToken
from app.config import get_settings
from app.utils.logger import setup_logger

logger = setup_logger(__name__)


class DecryptionError(Exception):
    """Raised when field decryption fails due to corrupted data or mismatched key."""
    pass


def _get_fernet() -> Fernet:
    settings = get_settings()
    key_str = settings.SESSION_ENCRYPTION_KEY.strip()
    try:
        return Fernet(key_str.encode("utf-8"))
    except Exception as e:
        logger.error(f"Invalid SESSION_ENCRYPTION_KEY configuration: {e}")
        raise ValueError(f"Invalid SESSION_ENCRYPTION_KEY: {e}") from e


def encrypt_field(plaintext: Optional[str]) -> Optional[str]:
    """
    Encrypt a plaintext string using Fernet.
    Returns ciphertext string or None if plaintext is empty/None.
    """
    if not plaintext:
        return plaintext

    f = _get_fernet()
    encrypted_bytes = f.encrypt(plaintext.encode("utf-8"))
    return encrypted_bytes.decode("utf-8")


def decrypt_field(ciphertext: Optional[str]) -> Optional[str]:
    """
    Decrypt a ciphertext string using Fernet.
    Raises DecryptionError if decryption fails (e.g. key mismatch, invalid token).
    """
    if not ciphertext:
        return ciphertext

    f = _get_fernet()
    try:
        decrypted_bytes = f.decrypt(ciphertext.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except (InvalidToken, Exception) as e:
        logger.error(f"Field decryption failure: {e}")
        raise DecryptionError("Failed to decrypt field — check SESSION_ENCRYPTION_KEY") from e
