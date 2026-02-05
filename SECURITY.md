# Política de Segurança

## Reportando Vulnerabilidades

Se você encontrou uma vulnerabilidade de segurança neste projeto, por favor **NÃO** abra uma issue pública.

Envie um e-mail para o proprietário do repositório (veja o perfil do GitHub) com os detalhes.

## Notas para Desenvolvedores

### Limpeza de Histórico Git
Se você clonou este repositório e ele continha chaves ou segredos em commits anteriores (antes da limpeza), considere essas chaves **comprometidas**.
- **Rotacione** (troque) todas as chaves de API, senhas de banco e segredos utilizados.
- Se for publicar este código, use ferramentas como `git filter-repo` ou `BFG Repo-Cleaner` para remover arquivos sensíveis do histórico do Git, ou inicie um novo repositório limpo:
  ```bash
  rm -rf .git
  git init
  git add .
  git commit -m "Initial commit"
  ```

### Variáveis de Ambiente
Nunca commite o arquivo `.env`. Use sempre `.env.example` para compartilhar o template de configuração.
