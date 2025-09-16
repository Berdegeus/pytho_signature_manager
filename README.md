# Capitalia — Microsserviço de Gestão de Assinaturas (Python, HTTP puro)

Este projeto implementa um microsserviço único para gestão de assinaturas (streaming) com HTTP puro (sem frameworks web), JWT manual, Ports & Adapters, Repository + Data Mapper, Unit of Work, Strategy para alternar entre SQLite/MySQL e sem ORMs.

## Requisitos

- Python 3.10+
- SQLite (builtin) ou MySQL (via PyMySQL)

## Setup rápido (SQLite)

1. Crie e ative um virtualenv e instale dependências:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r capitalia/requirements.txt
   ```

2. Inicialize e faça seed do SQLite:

   ```bash
   python -m capitalia.scripts.init_sqlite
   python -m capitalia.scripts.seed_sqlite
   ```

3. Execute o servidor (porta padrão 8080):

   ```bash
   python -m capitalia.main
   ```

4. Faça login e chame rotas protegidas (exemplos abaixo).

## Alternar para MySQL

1. Configure variáveis de ambiente (veja `capitalia/.env.example`):

   ```bash
   export DB_KIND=mysql
   export MYSQL_HOST=localhost
   export MYSQL_USER=capitalia_user
   export MYSQL_PASSWORD=senha
   export MYSQL_DB=capitalia
   export JWT_SECRET=troque-por-uma-chave-forte
   export PORT=8080
   ```

2. Instale dependências (PyMySQL já está em `requirements.txt`), aplique DDL e seed:

   ```bash
   pip install -r capitalia/requirements.txt
   # Execute os .sql no seu MySQL:
   # capitalia/scripts/init_mysql.sql e capitalia/scripts/seed_mysql.sql
   python -m capitalia.main
   ```

## Endpoints HTTP

- POST `/login` → `{email,password}` → `{token}`
- GET `/user/{id}/status` → aplica regras e persiste mudanças → `{user_id,plan,status}`
- POST `/user/{id}/upgrade`
- POST `/user/{id}/downgrade`
- POST `/user/{id}/suspend`
- POST `/user/{id}/reactivate`
- GET `/health` → `{status:"ok"}`

Suporte a CORS básico: `Access-Control-Allow-Origin: *` nas respostas. `OPTIONS` responde preflight com `Allow`, `Access-Control-Allow-Headers` e `Access-Control-Allow-Methods`.

Erros: `401` (token ausente/inválido), `404`, `422` (payload/estado inválido), `500` (erro interno sem stack trace).

### Exemplos curl

```bash
# Login (usuário seed)
curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"password123"}'

# Guarde o token
TOKEN="$(curl -s -X POST http://localhost:8080/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"password123"}' | jq -r .token)"

# Status efetivo (aplica expiração do trial)
curl -s http://localhost:8080/user/1/status -H "Authorization: Bearer $TOKEN"

# Healthcheck
curl -s http://localhost:8080/health

# Upgrade
curl -s -X POST http://localhost:8080/user/1/upgrade -H "Authorization: Bearer $TOKEN"

# Downgrade
curl -s -X POST http://localhost:8080/user/1/downgrade -H "Authorization: Bearer $TOKEN"

# Suspender (premium)
curl -s -X POST http://localhost:8080/user/1/suspend -H "Authorization: Bearer $TOKEN"

# Reativar (premium suspenso)
curl -s -X POST http://localhost:8080/user/1/reactivate -H "Authorization: Bearer $TOKEN"
```

## Configuração (env vars)

Veja `capitalia/.env.example`.

## Diagrama (ASCII) — Ports & Adapters

```
     +---------------------+         +----------------------+
     |  HTTP Handlers      |  uses   |  Domain Services     |
     |  (BaseHTTPRequest)  +--------->  (Use Cases)         |
     +---------------------+         +----------+-----------+
                 |                              |
                 | via UnitOfWork               | Entities/Rules
                 v                              v
        +--------+---------+            +------+-------+
        |   Ports (Repo)   |<-----------+  Domain     |
        |  UoW, Clock      |            |  Models     |
        +---+----------+---+            +--------------+
            ^          ^
            |          |
   +--------+--+   +---+---------+
   | SQLite   |   |   MySQL      |
   | Adapter  |   |   Adapter    |
   +----------+   +--------------+
```

## Fluxo de autenticação (JWT)

```
Client -> POST /login {email,password}
Server: valida credenciais -> assina JWT HS256 com exp=+3600s -> {token}
Client -> requests protegidas com Authorization: Bearer <token>
Server: verifica assinatura e exp -> autoriza -> executa caso de uso
```

## Referência de Rotas (API)

Base URL: `http://<host>:<PORT>` (default `http://localhost:8080`). Todas as respostas são JSON.

### POST /login
- Autenticação: pública (sem token).
- Corpo: `{"email": "<email>", "password": "<senha>"}`
- Sucesso 200: `{ "token": "<JWT>" }` (HS256, `exp` padrão 3600s).
- Erros:
  - 422 Unprocessable Entity: JSON inválido ou campos ausentes.
  - 401 Unauthorized: credenciais inválidas.
  - 500 Internal Server Error: erro inesperado (sem stack trace).

### GET /user/{id}/status
- Autenticação: `Authorization: Bearer <token>` (obrigatório).
- Autorização: somente o próprio usuário (`sub` do JWT deve ser igual a `{id}`).
- Ação: calcula status efetivo (expira trial após 30 dias) e persiste mudança se houver.
- Sucesso 200: `{ "user_id": <id>, "plan": "basic|trial|premium", "status": "active|suspended|expired" }`.
- Erros:
  - 401 Unauthorized: token ausente, inválido ou expirado.
  - 403 Forbidden: tentar acessar outro `{id}`.
  - 404 Not Found: usuário não encontrado.
  - 500 Internal Server Error: erro inesperado.

### POST /user/{id}/upgrade
- Autenticação: `Bearer`.
- Autorização: somente o próprio usuário (`sub == {id}`).
- Ação: `basic|trial → premium` e `status=active`.
- Corpo: vazio.
- Sucesso 200: `{ "user_id": <id>, "plan": "premium", "status": "active" }`.
- Erros:
  - 401 Unauthorized: token ausente/inválido/expirado.
  - 403 Forbidden: outro `{id}`.
  - 404 Not Found: usuário inexistente.
  - 422 Unprocessable Entity: plano atual não permite upgrade (já é premium).
  - 500 Internal Server Error.

### POST /user/{id}/downgrade
- Autenticação: `Bearer`.
- Autorização: somente o próprio usuário (`sub == {id}`).
- Ação: `premium → basic` e `status=active`.
- Corpo: vazio.
- Sucesso 200: `{ "user_id": <id>, "plan": "basic", "status": "active" }`.
- Erros:
  - 401 Unauthorized; 403 Forbidden; 404 Not Found.
  - 422 Unprocessable Entity: não está em premium.
  - 500 Internal Server Error.

### POST /user/{id}/suspend
- Autenticação: `Bearer`.
- Autorização: somente o próprio usuário (`sub == {id}`).
- Ação: suspende somente se `plan=premium`.
- Corpo: vazio.
- Sucesso 200: `{ "user_id": <id>, "plan": "premium", "status": "suspended" }`.
- Erros:
  - 401 Unauthorized; 403 Forbidden; 404 Not Found.
  - 422 Unprocessable Entity: não está em premium.
  - 500 Internal Server Error.

### POST /user/{id}/reactivate
- Autenticação: `Bearer`.
- Autorização: somente o próprio usuário (`sub == {id}`).
- Ação: reativa somente se `plan=premium` e `status=suspended`.
- Corpo: vazio.
- Sucesso 200: `{ "user_id": <id>, "plan": "premium", "status": "active" }`.
- Erros:
  - 401 Unauthorized; 403 Forbidden; 404 Not Found.
  - 422 Unprocessable Entity: não está suspenso/premium.
  - 500 Internal Server Error.

### Autenticação e JWT
- Header: `Authorization: Bearer <token>`.
- Assinatura: HS256; payload inclui `sub` (id do usuário), `email`, `plan`, `iat`, `exp`.
- Expiração padrão: 3600s (1h).

### Códigos de erro (resumo)
- 200 OK: operação bem-sucedida.
- 401 Unauthorized: token ausente/inválido/expirado (ou login inválido).
- 403 Forbidden: usuário tentando acessar/modificar outro `{id}`.
- 404 Not Found: recurso inexistente (ex.: usuário).
- 405 Method Not Allowed: método HTTP incorreto para a rota (ex.: usar GET onde é POST).
- 422 Unprocessable Entity: JSON inválido/campos obrigatórios ausentes ou regra de negócio violada.
- 500 Internal Server Error: erro inesperado; mensagem genérica (sem stack trace).

## AWS RDS (MySQL) — Passo a passo

1) Criar instância RDS MySQL

- Console AWS → RDS → Create database → MySQL 8.x
- Template: Free tier (se disponível)
- DB instance identifier: `capitalia-mysql`
- Defina master username/password
- VPC default
- Public access: Yes (apenas para TDE; produção: Private + bastion)
- Security Group: permita Inbound TCP 3306 somente do seu IP
- Crie e aguarde status `Available`

2) Obter endpoint

- Em Databases → selecione a instância → copie Endpoint e Port (3306)

3) Criar database lógico e usuário

```sql
mysql -h <ENDPOINT> -P 3306 -u <MASTER_USER> -p
CREATE DATABASE capitalia CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
CREATE USER 'capitalia_user'@'%' IDENTIFIED BY '<senha-forte>';
GRANT ALL PRIVILEGES ON capitalia.* TO 'capitalia_user'@'%';
FLUSH PRIVILEGES;
```

4) Aplicar DDL e seed

- Rode `capitalia/scripts/init_mysql.sql` e `capitalia/scripts/seed_mysql.sql` no DB `capitalia`.

5) Configurar o microsserviço

```bash
export DB_KIND=mysql
export MYSQL_HOST=<endpoint RDS>
export MYSQL_USER=capitalia_user
export MYSQL_PASSWORD=<senha>
export MYSQL_DB=capitalia
export JWT_SECRET=<segredo forte>
pip install -r capitalia/requirements.txt
python capitalia/main.py
```

## Testes

Execute:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```
