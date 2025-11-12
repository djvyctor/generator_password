# Instruções para Release v0.1.0-alpha

## Preparação

1. Certifique-se de que todos os testes passam:
   ```bash
   pytest
   ```

2. Verifique se não há erros no código:
   ```bash
   python -m src.ui.app_window
   ```

## Criando a Release no GitHub

### Opção 1: Via Interface Web

1. Vá para: https://github.com/djvyctor/generator_password/releases/new
2. Preencha:
   - **Tag version**: `v0.1.0-alpha`
   - **Release title**: `v0.1.0-alpha - Initial Alpha Release`
   - **Description**: Copie o conteúdo do CHANGELOG.md para esta versão
3. Marque a opção "This is a pre-release"
4. Clique em "Publish release"

### Opção 2: Via Git Command Line

```bash
# Adicionar todos os arquivos
git add .

# Commit das mudanças
git commit -m "Release v0.1.0-alpha: Initial alpha version with basic features"

# Push para o repositório
git push origin main

# Criar a tag
git tag -a v0.1.0-alpha -m "Initial alpha release"

# Push da tag
git push origin v0.1.0-alpha
```

Depois vá no GitHub e crie a release a partir da tag.

## Checklist de Release

- [x] LICENSE criada (MIT)
- [x] VERSION definida (0.1.0-alpha)
- [x] CHANGELOG.md documentado
- [x] setup.py configurado
- [ ] Testes passando
- [ ] Código sem erros
- [ ] Commit e push realizados
- [ ] Tag criada
- [ ] Release publicada no GitHub

## Notas

- Esta é uma versão **alpha**, portanto ainda não está pronta para produção
- Funcionalidades básicas estão implementadas e funcionais
- Versões futuras incluirão features avançadas (gerador, alertas, etc.)
