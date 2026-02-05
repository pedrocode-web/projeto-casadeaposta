# Casa de Apostas

Este é um projeto de demonstração de uma plataforma de apostas simples, desenvolvido com Node.js, Express e SQLite.

**⚠️ PROJETO PARA FINS EDUCACIONAIS E DE PORTFÓLIO. NÃO USE EM PRODUÇÃO SEM AUDITORIA.**

## Funcionalidades

- **Autenticação**: Login, Registro, Recuperação de Senha, Verificação de E-mail.
- **Jogos**:
  - Crash (Multiplicador progressivo)
  - Mines (Campo minado)
  - Slots (Caça-níqueis simples)
- **Carteira**:
  - Depósitos via Pix (integração simulada/QR Code estático ou dinâmica com provedor)
  - Saldo em tempo real
- **Painel Admin**:
  - Gerenciamento de usuários
  - Aprovação manual de depósitos
  - Ajuste de saldos
  - Métricas simples

## Tecnologias

- **Backend**: Node.js, Express
- **Banco de Dados**: SQLite3
- **Frontend**: EJS (Server-side rendering), CSS puro
- **Segurança**: Helmet, bcrypt, Express Session (com SQLite Store)

## Como Rodar

1.  **Instalar dependências**:
    ```bash
    npm install
    ```

2.  **Configurar Variáveis de Ambiente**:
    - Copie o arquivo de exemplo:
      ```bash
      cp .env.example .env
      ```
    - Edite o arquivo `.env` com suas configurações (Banco, E-mail, Pix, etc).
    - **Importante**: Defina um `SESSION_SECRET` forte.

3.  **Configurar Admin Inicial**:
    - No arquivo `.env`, defina `ADMIN_EMAIL` e `ADMIN_PASSWORD`.
    - Ao iniciar a aplicação pela primeira vez, este usuário será criado automaticamente.

4.  **Iniciar o Servidor**:
    ```bash
    npm start
    ```
    O servidor rodará em `http://localhost:3000` (ou na porta definida no `.env`).

## Estrutura do Projeto

- `server.js`: Ponto de entrada e lógica principal (monólito modular).
- `db.js`: Conexão e migrações do SQLite.
- `views/`: Templates EJS.
- `public/`: Arquivos estáticos (CSS, JS do cliente).
- `sessions.sqlite`: Armazenamento de sessões (ignorado no git).
- `database.sqlite`: Banco de dados principal (ignorado no git).

## Segurança

Este projeto foi configurado para não expor credenciais no repositório.
- **Segredos**: Todas as chaves (API Keys, Secrets) devem estar no `.env`.
- **Git**: Arquivos sensíveis (`.env`, `*.sqlite`, logs) estão no `.gitignore`.

Caso encontre alguma vulnerabilidade, por favor não abra uma issue pública. Veja `SECURITY.md`.

## Licença

Todos os direitos reservados. Este código é fornecido apenas para demonstração de portfólio.
