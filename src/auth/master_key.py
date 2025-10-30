import os
import base64
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from utils.crypto import encrypt_data, decrypt_data

#Caminho para armazenar a senha master criptografada
MASTER_KEY_PATH = "data/master.key"

#Função que vai gerar a chave a partir da senha master usando o PBKDF2
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashlib.sha256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

#Cria e salva a senha master
def create_master_key(password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    with open(MASTER_KEY_PATH, 'wb') as f:
        f.write(salt + key)

#Verifica se a senha master está correta
def verify_master_key(password: str) -> bool:
    if not os.path.exists(MASTER_KEY_PATH):
        return False
    with open(MASTER_KEY_PATH,'rb') as f:
        data = f.read()
        salt, stored_key = data[:16], data[16:]
        key = derive_key(password, salt)
        return key == stored_key