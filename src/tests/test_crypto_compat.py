import os
import json
from cryptography.fernet import Fernet
from src.utils.crypto import encrypt_data, decrypt_data, is_v2_envelope, is_fernet_token
from src.auth.master_key import derive_key


def test_v2_roundtrip():
    """Encrypt/decrypt roundtrip usando o novo formato v2 (AES-GCM)."""
    password = "test_password"
    salt = os.urandom(16)
    key = derive_key(password, salt)  # retorna chave em base64 (compat com Fernet)

    plaintext = "hello v2"
    token = encrypt_data(plaintext, key)

    # token deve ser bytes contendo JSON com nonce+ciphertext
    assert isinstance(token, (bytes, bytearray))
    assert is_v2_envelope(token)

    out = decrypt_data(token, key)
    assert out == plaintext


def test_legacy_fernet_decrypt():
    """Garantir que um token Fernet legado é corretamente desserializado (migração)."""
    password = "another_pass"
    salt = os.urandom(16)
    key = derive_key(password, salt)

    # criar token Fernet com a mesma chave derivada
    f = Fernet(key)
    original = "legacy data"
    legacy_token = f.encrypt(original.encode("utf-8"))

    assert is_fernet_token(legacy_token)

    out = decrypt_data(legacy_token, key)
    assert out == original
