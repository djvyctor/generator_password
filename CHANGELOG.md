# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-alpha] - 2025-11-12

### Added
- Sistema de autenticação com senha master (PBKDF2 + 100k iterações)
- Adicionar senhas com formulário inline (sem diálogos)
- Remover senhas do cofre
- Copiar senhas para área de transferência
- Visualização de senhas em lista (Treeview)
- Criptografia dupla camada (Fernet + AES-GCM)
- Interface gráfica dark theme (CustomTkinter)
- Sistema de migração v1→v2 para criptografia
- Armazenamento seguro em `data/vault.json`
- Licença MIT

### Security
- Criptografia forte com PBKDF2-HMAC-SHA256
- Salt único por instalação
- Compatibilidade retroativa mantida durante migração

### Notes
- Esta é a primeira versão alpha
- Features básicas implementadas e funcionais
- Funcionalidades avançadas (gerador de senhas, alertas, links, expiração) serão adicionadas em versões futuras
