import os
import pytest
from pathlib import Path

from src.auth.master_key import create_master_key, verify_master_key, derive_key
from src.features.manager import add_password, get_password, remove_password, VAULT_PATH
from src.auth.master_key import MASTER_KEY_PATH

_TEST_PASSWORD = "teste123"


@pytest.fixture
def tmp_data_dir(tmp_path):
    """Cria diretório temporário data/ dentro do tmp_path para isolar testes."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    return data_dir


@pytest.fixture
def patch_paths(monkeypatch, tmp_data_dir):
    """Patch MASTER_KEY_PATH e VAULT_PATH para apontar para o diretório temporário."""
    master_key_path = str(tmp_data_dir / "master.key")
    vault_path = str(tmp_data_dir / "vault.json")
    monkeypatch.setattr("src.auth.master_key.MASTER_KEY_PATH", master_key_path)
    monkeypatch.setattr("src.features.manager.VAULT_PATH", vault_path)
    return master_key_path, vault_path


@pytest.fixture
def chave(patch_paths):
    """Fixture para chave derivada do salt."""
    master_key_path = patch_paths[0]
    create_master_key(_TEST_PASSWORD)
    with open(master_key_path, "rb") as f:
        salt = f.read()[:16]
    return derive_key(_TEST_PASSWORD, salt)


def test_add_and_get_password(chave, patch_paths):
    add_password("Email", "user@email.com", "senhaemail", chave)
    dados = get_password("Email", chave)
    assert dados["username"] == "user@email.com"
    assert dados["password"] == "senhaemail"


def test_remove_password(chave, patch_paths):
    remove_password("Email", chave)
    dados = get_password("Email", chave)
    assert dados is None
