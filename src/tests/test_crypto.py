import pytest
from src.utils.crypto_new import (
    generate_salt,
    derive_key,
    encrypt,
    decrypt,
    generate_password,
)

#Teste do gemerate_salt
def test_generate_salt_default_length():
    """Testa generate_sault() para salt com tamanho de 16 bytes"""
    salt = generate_salt()
    assert len(salt) == 16
    assert isinstance(salt, bytes)

def test_generate_salt_custom_length():
    """Testa se generate_salt aceita tamanho diferente"""
    salt = generate_salt(length=32)
    assert len(salt) == 32

#teste do derive_key
def test_derive_key_deterministic():
    """Testa se derive_key gera a mesma chave para mesma senha mais salt"""
    password = "Teste_Senha_123"
    salt = b"salt_fixa_teste_"
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert key1 == key2
    assert len(key1) == 32

#Teste do generate_password
def test_generate_password_length():
    """Testa se generate_password respeita comprimento pedido"""
    pwd = generate_password(length=20)
    assert len(pwd) == 20

def test_generate_password_character_classes():
    """Testa se a senha gerada contém caracteres das classes pedidas"""
    pwd = generate_password(
        length=12,
        use_upper=True,
        use_lower=True,
        use_digits=True,
        use_symbols=True
    )

    assert any(c.isupper() for c in pwd)
    assert any(c.islower() for c in pwd)
    assert any(c.isdigit() for c in pwd)
    assert any(not c.isalnum() for c in pwd)