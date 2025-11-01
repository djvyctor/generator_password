import os
import pytest
from src.auth.master_key import create_master_key, verify_master_key, derive_key
from src.features.manager import add_password, get_password, remove_password

senha = "teste123"

@pytest.fixture(scope="module")
def chave():
    create_master_key(senha)
    with open("data/master.key", "rb") as f:
        salt = f.read()[:16]
    return derive_key(senha, salt)

def test_add_and_get_password(chave):
    add_password("Email", "user@email.com", "senhaemail", chave)
    dados = get_password("Email", chave)
    assert dados["username"] == "user@email.com"
    assert dados["password"] == "senhaemail"

def test_remove_password(chave):
    remove_password("Email", chave)
    dados = get_password("Email", chave)
    assert dados is None
