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
