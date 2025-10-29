from cryptography.fernet import Fernet
import os

#Essa função gera uma chave para criar senha master e criptografa vault
def generate_key():
    return Fernet.generate_key()

#Salvar chave em arquivo
def save_key(path: str, key: bytes):
    with open(path, 'wb') as f:
        f.write(key)

#Carrega a chave do arquivo wb
def load_key(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()
    
#Criptografar dados
def encrypt_data(data: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data.encode())

#Descriptografar dados
def decrypt_data(token: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token).decode()