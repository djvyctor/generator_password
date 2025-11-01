import json
import os
from utils.crypto import encrypt_data, decrypt_data

VAULT_PATH = "data/vault.json"

def load_vault(key: bytes) -> dict:
    if not os.path.exists(VAULT_PATH):
        return {}
    with open(VAULT_PATH, 'rb') as f:
        encrypted_data = f.read()
    decrypted = decrypt_data(encrypted_data, key)
    return json.loads(decrypted)

def save_vault(data: dict, key: bytes):
    encrypted = encrypt_data(json.dumps(data), key)
    with open(VAULT_PATH, 'wb') as f:
        f.write(encrypted)

def add_password(service: str, username: str, password: str, key: bytes):
    vault = load_vault(key)
    vault[service] = {"username": username, "password": password}
    save_vault(vault, key)

def remove_password(service: str, key: bytes):
    vault = load_vault(key)
    if service in vault:
        del vault[service]
        save_vault(vault, key)

def get_password(service: str, key: bytes) -> dict | None:
    vault = load_vault(key)
    return vault.get(service)
