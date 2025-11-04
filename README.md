🔐 Password Manager App

Hey! Looking for a tool that's both simple and powerful?

I have a solution!!! 🚀

I'm starting the process of creating a simple Python app. When you run it, it will ask for your master password to grant access.

## ⚡ Features

Based on that, this app will have features like:

🛠 Generating complex passwords based on the character length you choose.

💾 Storing passwords for various apps or websites you use, including the link to go directly to the site or app.

⚠️ Warning you if you overuse the same password in different places, suggesting you change it.

Each password will also have an expiration date. But don't worry, your password won't just disappear or change out of the blue!
The app will simply advise you to change it on the website where it's used, so you can have better security.

## � Quick Start

### Prerequisites

- Python 3.11+ with pip
- Ambiente virtual (venv) recomendado

### Installation

1. Clone o repositório e crie um ambiente virtual:
```powershell
git clone https://github.com/djvyctor/generator_password.git
cd generator_password
python -m venv venv
.\venv\Scripts\activate
```

2. Instale as dependências:
```powershell
pip install -r requirements.txt
```

### Primeiro Uso

1. Inicialize o vault com uma senha master forte:
```powershell
python -c "from src.auth.master_key import create_master_key; create_master_key('SUA_SENHA_FORTE')"
```

2. Execute o aplicativo (interface gráfica em desenvolvimento):
```powershell
python -m src.ui.app_window
```

## 🔧 Development

### Running Tests

Execute a suíte de testes completa:
```powershell
python -m pytest
```

Ou execute testes específicos:
```powershell
python -m pytest src/tests/test_manager.py   # testes do manager
python -m pytest src/tests/test_crypto.py    # testes de criptografia
```

### Vault Management

O aplicativo usa dois arquivos principais:
- `data/master.key`: armazena salt + chave derivada da senha master
- `data/vault.json`: armazena senhas encriptadas (formato v2: AES-GCM)

Para resetar o vault:
1. Faça backup dos arquivos atuais (se necessário)
2. Delete `data/master.key` e `data/vault.json`
3. Recrie com uma nova senha master

Para rotacionar a senha master:
```powershell
# Em breve: script de rotação de chave
python scripts/rotate_master.py
```

### Formatos de Armazenamento

O vault suporta dois formatos de token:
1. Legacy (Fernet): tokens começando com "gAAAA"
2. v2 (AES-GCM): envelope JSON com nonce + ciphertext em base64

A migração é automática:
- Leitura: tenta Fernet primeiro, depois v2
- Escrita: sempre usa v2 (migração gradual)

## ���🛡️ Goal

Our main concern is to maintain a safe and stress-free environment on your desktop.

Follow along with the project until its official release version =)

Thanks!!! 🙌

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.
