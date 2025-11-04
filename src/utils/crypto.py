"""Utilitários de criptografia.

Este módulo fornece duas famílias de utilitários:

- Helpers legados baseados em Fernet usados pelo restante da aplicação:
  `generate_key`, `save_key`, `load_key`, `encrypt_data`, `decrypt_data`.
- Utilitários mais novos (PBKDF2 + AES-GCM) usados por testes e para
  migração futura: `generate_salt`, `derive_key`, `encrypt`, `decrypt`,
  `generate_password`.

Ambos coexistem aqui para compatibilidade durante a migração para um
esquema derivado (PBKDF2 + AES-GCM).
"""

from __future__ import annotations

import base64
import os
import secrets
from typing import Dict

from cryptography.fernet import Fernet, InvalidToken
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


# -----------------
# Legado / Fernet
# -----------------

def generate_key() -> bytes:
    """Gera uma nova chave Fernet (bytes base64 urlsafe).

    Usada pela criptografia legada do vault.
    """
    return Fernet.generate_key()


def save_key(path: str, key: bytes):
    with open(path, "wb") as f:
        f.write(key)


def load_key(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def encrypt_data(data: str, key: bytes) -> bytes:
        """Compat wrapper: encripta dados para o vault.

        Comportamento:
        - Para escrita de novos dados, gravamos no formato v2 (JSON com nonce+ciphertext,
            usando AES-GCM). Isso permite migrar gradualmente para o novo esquema.
        - Mantemos a assinatura/assinatura da função para compatibilidade com o resto do app.
        """
        return encrypt_data_v2(data, key)


def decrypt_data(token: bytes, key: bytes) -> str:
    """Descriptografa um token do vault e retorna a string decodificada.

    Estratégia de compatibilidade:
    1. Tenta descriptografar como Fernet (legado).
    2. Se falhar com InvalidToken, tenta o novo envelope v2 (JSON com nonce/ciphertext).
    3. Se nenhum funcionar, propaga a exceção original.
    """
    # Primeiro tente Fernet (legado)
    try:
        f = Fernet(key)
        return f.decrypt(token).decode()
    except InvalidToken:
        # tentar novo formato v2
        return decrypt_data_v2(token, key)


# -----------------
# Compat / v2 (AES-GCM envelope)
# -----------------
import json


def _normalize_key_for_aes(key: bytes) -> bytes:
    """Normaliza a chave recebida para 32 bytes brutos para uso com AESGCM.

    O `master_key.derive_key` retorna uma chave codificada em base64 urlsafe (como o
    Fernet espera). Para AES-GCM precisamos dos bytes brutos (32 bytes). Se a chave
    já for bruta (len == 32) retornamos ela; caso contrário tentamos decodificar base64.
    """
    if isinstance(key, str):
        key = key.encode()
    # chave já bruta?
    if len(key) == _KEY_SIZE:
        return key
    try:
        # tenta urlsafe base64
        return base64.urlsafe_b64decode(key)
    except Exception:
        # fallback: tentar base64 padrão
        return base64.b64decode(key)


def is_v2_envelope(data: bytes) -> bool:
    """Detecta heurísticamente se `data` é um envelope v2 (JSON com nonce+ciphertext)."""
    try:
        obj = json.loads(data.decode("utf-8"))
        return isinstance(obj, dict) and "nonce" in obj and "ciphertext" in obj
    except Exception:
        return False


def is_fernet_token(data: bytes) -> bool:
    """Heurística simples para verificar se `data` parece um token Fernet (sem decodificar).

    Observação: usada apenas para sinais diagnósticos; a função de decrypt tenta Fernet
    diretamente e cai para v2 se necessário.
    """
    try:
        s = data.decode("ascii")
        return s.startswith("gAAAA")
    except Exception:
        return False


def encrypt_data_v2(data: str, key: bytes) -> bytes:
    """Encripta `data` (string) usando AES-GCM e retorna um envelope JSON em bytes.

    O envelope contém 'nonce' e 'ciphertext' (ambos em base64 padrão).
    """
    aes_key = _normalize_key_for_aes(key)
    aesgcm = AESGCM(aes_key)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, data.encode("utf-8"), associated_data=None)
    envelope = {"nonce": _b64encode(nonce), "ciphertext": _b64encode(ct)}
    return json.dumps(envelope).encode("utf-8")


def decrypt_data_v2(token: bytes, key: bytes) -> str:
    """Descriptografa um envelope v2 (JSON bytes) e retorna a string original.

    Lança exceções de parsing/InvalidTag se o conteúdo for inválido.
    """
    if not is_v2_envelope(token):
        raise InvalidToken
    obj = json.loads(token.decode("utf-8"))
    aes_key = _normalize_key_for_aes(key)
    plaintext = decrypt(obj, aes_key)
    return plaintext.decode("utf-8")


# -----------------
# Novos utilitários (PBKDF2 + AES-GCM)
# -----------------

# Constantes para o esquema de chave derivada
_SALT_SIZE = 16
_NONCE_SIZE = 12
_KEY_SIZE = 32
_KDF_ITERATIONS = 390_000


def generate_salt(length: int = _SALT_SIZE) -> bytes:
    """Retorna bytes de salt gerados criptograficamente seguros."""
    return secrets.token_bytes(length)


def derive_key(master_password: str, salt: bytes, iterations: int = _KDF_ITERATIONS) -> bytes:
    """Deriva uma chave de 32 bytes a partir de uma senha e um salt usando PBKDF2-HMAC-SHA256.

    Retorna bytes brutos (32 bytes).
    """
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=_KEY_SIZE, salt=salt, iterations=iterations)
    return kdf.derive(master_password.encode("utf-8"))


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(data_str: str) -> bytes:
    return base64.b64decode(data_str.encode("ascii"))


def encrypt(plaintext: bytes, key: bytes) -> Dict[str, str]:
    """Criptografa bytes com AES-GCM e retorna um dict com componentes em base64.

    O dicionário retornado contém 'nonce' e 'ciphertext' (strings base64).
    """
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(_NONCE_SIZE)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return {"nonce": _b64encode(nonce), "ciphertext": _b64encode(ct)}


def decrypt(enc: Dict[str, str], key: bytes) -> bytes:
    """Descriptografa um dicionário produzido por :func:`encrypt` e retorna os bytes em claro.

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
    """Gera uma senha criptograficamente segura com as classes de caracteres solicitadas."""
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


__all__ = [
    # legado
    "generate_key",
    "save_key",
    "load_key",
    "encrypt_data",
    "decrypt_data",
    # novos
    "generate_salt",
    "derive_key",
    "encrypt",
    "decrypt",
    "generate_password",
]