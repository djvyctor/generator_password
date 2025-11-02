"""Helpers de criptografia (PBKDF2 + AES-GCM) usados por testes e migração.

Fornece funções para gerar salt, derivar chave, encriptar/desencriptar com
AES-GCM e gerar senhas seguras.
"""

from __future__ import annotations

import base64
import secrets
from typing import Dict

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constantes
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KEY_SIZE = 32
_KDF_ITERATIONS = 390_000


def generate_salt(length: int = _SALT_SIZE) -> bytes:
    """Gera um salt aleatório (bytes) de tamanho `length`."""
    return secrets.token_bytes(length)


def derive_key(master_password: str, salt: bytes, iterations: int = _KDF_ITERATIONS) -> bytes:
    """Deriva uma chave de 32 bytes a partir da `master_password` e `salt`."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=_KEY_SIZE, salt=salt, iterations=iterations)
    return kdf.derive(master_password.encode("utf-8"))


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode("ascii"))


def encrypt(plaintext: bytes, key: bytes) -> Dict[str, str]:
    """Criptografa `plaintext` com `key` (AES-GCM) e retorna um dict com base64.

    Retorna {'nonce': ..., 'ciphertext': ...} (strings em base64).
    """
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {"nonce": _b64encode(nonce), "ciphertext": _b64encode(ct)}


def decrypt(enc: Dict[str, str], key: bytes) -> bytes:
    """Descriptografa o envelope `enc` e retorna os bytes em claro.

    Lança InvalidTag se a autenticação falhar.
    """
    nonce = _b64decode(enc["nonce"]) if "nonce" in enc else b""
    ct = _b64decode(enc["ciphertext"]) if "ciphertext" in enc else b""
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ct, associated_data=None)
    except InvalidTag:
        raise


def generate_password(length: int = 16, use_upper: bool = True, use_lower: bool = True,
                      use_digits: bool = True, use_symbols: bool = True) -> str:
    """Gera uma senha segura com as classes solicitadas (maiúsculas/minúsculas/dígitos/símbolos)."""
    if length <= 0:
        raise ValueError("length must be > 0")

    pools = []
    if use_lower:
        pools.append("abcdefghijklmnopqrstuvwxyz")
    if use_upper:
        pools.append("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    if use_digits:
        pools.append("0123456789")
    if use_symbols:
        pools.append("!@#$%&*()-_=+[]{};:,.<>?/~")

    if not pools:
        raise ValueError("At least one character class must be enabled")

    password_chars = []
    for pool in pools:
        if len(password_chars) < length:
            password_chars.append(secrets.choice(pool))

    all_chars = "".join(pools)
    while len(password_chars) < length:
        password_chars.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
