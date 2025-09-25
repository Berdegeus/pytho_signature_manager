# Capitalia

**Alunos**
- Bernardo Roorda — @Berdegeus
- Bruno Pires — @bpires
- Eduardo Schneider — @Xinaidinho
- Dirceu Djunior — @DirceuDjunior

# Projeto Disciplinar – Design Patterns

## Orientações Gerais

Este repositório contém o microsserviço **Capitalia**, entregue pela equipe acima para a disciplina **Design Patterns**. O serviço foi desenvolvido a partir do projeto de referência e evoluído para atender ao cenário comercial escolhido pela equipe, mantendo o foco em **código puro**, **refatoração**, **código limpo** e na aplicação de múltiplos **Design Patterns (GoF e arquiteturais)**.

O objetivo central é **desenvolver um microsserviço de domínio** utilizando o servidor HTTP nativo do Python (`http.server`), demonstrando como padrões de projeto aceleram a adaptação do código a diferentes bancos de dados, regras de negócio e integrações externas.

---

## Atividades Avaliativas

### N1 – Prática Individual
- Refatoração do fluxo de autenticação e das regras de assinatura recebidas no enunciado original.
- Aplicação e justificativa no código do padrão **Strategy** para alternância de repositórios, mantendo o microsserviço em **HTTP puro**.

### N2 – Trabalho em Equipe
- Reconstrução arquitetural seguindo **Ports & Adapters (Clean Architecture)**, separando domínio, aplicação e infraestrutura.
- Demonstração do microsserviço rodando com **SQLite** e **MySQL**, alternáveis via variáveis de ambiente e fábricas de repositório.
- Documentação dos padrões adotados (**Repository + Data Mapper**, **Unit of Work**, **Strategy**, **Adapter**).

### N3 – Prática Individual
- Análise das decisões arquiteturais e registro do racional em comentários e documentação.
- Cada integrante versionou ao menos um padrão na área do código em que atuou (regras de domínio, persistência, autenticação ou servidor) e explicou sua aplicação na base de código.

---

## Requisitos Obrigatórios

- Microsserviço de domínio implementado em **Python 3.10+**, utilizando apenas o módulo `http.server` para atender requisições HTTP.
- Ausência de frameworks de alto nível; somente bibliotecas padrão e dependências mínimas (PyMySQL) quando necessário.
- Aplicação de técnicas de refatoração e **código limpo** em todo o fluxo de autenticação, autorização e gestão de assinaturas.
- Uso de pelo menos **3 Design Patterns**: Strategy (seleção de banco), Repository/Data Mapper, Unit of Work e Adapter.
- Suporte à alternância entre **SQLite** e **MySQL** por meio de variáveis de ambiente e fábricas de conexão.
- Commits identificáveis de cada integrante da equipe.

---

## Equipe

- Nome do Projeto: **Capitalia – Microsserviço de Gestão de Assinaturas**
- Integrantes:
  - Bernardo Roorda – @Berdegeus
  - Bruno Pires – @bpires
  - Eduardo Schneider – @Xinaidinho
  - Dirceu Djunior – @DirceuDjunior

---

## Contexto Comercial da Aplicação

O Capitalia atende a um **serviço de streaming** que oferece planos *trial*, *basic* e *premium*. O microsserviço concentra as regras de ciclo de vida de uma assinatura, permitindo consultar o status efetivo, realizar *upgrade/downgrade*, suspender e reativar planos premium. Os padrões aplicados tornam o domínio flexível: o **Strategy** troca rapidamente entre SQLite e MySQL; **Repository + Data Mapper** encapsulam o acesso a dados; o **Unit of Work** garante consistência transacional; e a arquitetura **Ports & Adapters** desacopla o servidor HTTP do núcleo de regras, facilitando novas integrações.

---

## Stack Tecnológica

- **Linguagem de Programação:** Python 3.10+ (`http.server`, `dataclasses`, `sqlite3`, `json`, etc.)
- **Banco de Dados:** SQLite (builtin) e MySQL (via `PyMySQL`), alternáveis via variáveis de ambiente
- **Arquitetura:** Clean Architecture / Ports & Adapters com Repository + Data Mapper, Unit of Work e Strategy
- **Autenticação:** JWT assinado manualmente (HS256) com expiração configurável

---

## Estrutura Recomendada

```
/README.md            → visão geral do projeto
/capitalia/
  main.py             → ponto de entrada do servidor HTTP nativo
  config.py           → leitura de variáveis de ambiente e fábricas de conexão
  /app/               → handlers HTTP, roteamento e servidor (HttpServer)
  /domain/            → entidades, regras de negócio, estratégias de status
  /ports/             → contratos de repositório, clock e outros ports
  /adapters/          → implementações SQLite/MySQL (Repository, Data Mapper, Unit of Work)
  /scripts/           → inicialização e seed de bancos (SQLite/MySQL)
/router/              → protótipos de rotas utilizados em iterações anteriores
/tests/               → testes unitários e integrados (unittest)
```

---

# Servidores Nativos por Linguagem

Este documento apresenta exemplos mínimos de servidores HTTP utilizando apenas recursos nativos de cada linguagem, sem frameworks adicionais.

---

## JavaScript / TypeScript (Node.js)

**Módulo nativo:** `http`

```javascript
const http = require('http');

const server = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('Hello World\n');
});

server.listen(3000, () => {
  console.log('Servidor rodando em http://localhost:3000');
});
```

---

## Java

**Mais puro:** `com.sun.net.httpserver.HttpServer` (desde Java 6)

```java
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpExchange;
import java.io.OutputStream;

public class Main {
    public static void main(String[] args) throws Exception {
        HttpServer server = HttpServer.create(new java.net.InetSocketAddress(8080), 0);
        server.createContext("/", new MyHandler());
        server.start();
    }

    static class MyHandler implements HttpHandler {
        public void handle(HttpExchange t) throws java.io.IOException {
            String response = "Hello World";
            t.sendResponseHeaders(200, response.length());
            OutputStream os = t.getResponseBody();
            os.write(response.getBytes());
            os.close();
        }
    }
}
```

---

## Python

**Mais puro:** módulo `http.server` (stdlib)

```python
from http.server import BaseHTTPRequestHandler, HTTPServer

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Hello World")

server = HTTPServer(('localhost', 8000), MyHandler)
server.serve_forever()
```

---

## C# (.NET)

**Mais puro:** `HttpListener` (sem ASP.NET)

```csharp
using System;
using System.Net;
using System.Text;

class Program {
    static void Main() {
        HttpListener listener = new HttpListener();
        listener.Prefixes.Add("http://localhost:8080/");
        listener.Start();
        Console.WriteLine("Servidor rodando...");

        while (true) {
            HttpListenerContext context = listener.GetContext();
            HttpListenerResponse response = context.Response;
            string responseString = "Hello World";
            byte[] buffer = Encoding.UTF8.GetBytes(responseString);
            response.ContentLength64 = buffer.Length;
            response.OutputStream.Write(buffer, 0, buffer.Length);
            response.OutputStream.Close();
        }
    }
}
```

---

## PHP

**Mais puro:** servidor embutido (desde PHP 5.4)

Rodar no terminal:

```bash
php -S localhost:8000
```

E um `index.php` mínimo:

```php
<?php
echo "Hello World";
?>
```

---

## Go (Golang)

**Mais puro:** pacote `net/http`

```go
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintln(w, "Hello World")
}

func main() {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}
```

---

## Ruby

**Mais puro:** WEBrick (stdlib até Ruby 3.0; depois como gem)

```ruby
require 'webrick'

server = WEBrick::HTTPServer.new(:Port => 8000)
server.mount_proc '/' do |req, res|
  res.body = 'Hello World'
end
trap 'INT' do server.shutdown end
server.start
```

---

## Guia de Execução do Microsserviço

### Requisitos

- Python 3.10+
- SQLite (builtin) ou MySQL (via PyMySQL)

### Setup rápido (SQLite)

1. Crie e ative um virtualenv e instale as dependências:

   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r capitalia/requirements.txt
   ```

2. Inicialize e faça seed do banco SQLite:

   ```bash
   python -m capitalia.scripts.init_sqlite
   python -m capitalia.scripts.seed_sqlite
   ```

3. Execute o servidor (porta padrão 8080):

   ```bash
   python -m capitalia.main
   ```

4. Faça login e utilize as rotas protegidas (exemplos abaixo).

### Alternar para MySQL

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

2. Instale as dependências (PyMySQL já está em `requirements.txt`), aplique DDL e seed:

   ```bash
   pip install -r capitalia/requirements.txt
   # Execute os .sql no seu MySQL:
   # capitalia/scripts/init_mysql.sql e capitalia/scripts/seed_mysql.sql
   python -m capitalia.main
   ```

### Endpoints HTTP

- POST `/login` → `{email,password}` → `{token}`
- GET `/user/{id}/status` → aplica regras e persiste mudanças → `{user_id,plan,status}`
- POST `/user/{id}/upgrade`
- POST `/user/{id}/downgrade`
- POST `/user/{id}/suspend`
- POST `/user/{id}/reactivate`
- GET `/health` → `{status:"ok"}`

Suporte a CORS básico: `Access-Control-Allow-Origin: *` nas respostas. `OPTIONS` responde preflight com `Allow`, `Access-Control-Allow-Headers` e `Access-Control-Allow-Methods`.

Erros comuns: `401` (token ausente/inválido), `404`, `422` (payload/estado inválido), `500` (erro interno sem stack trace).

#### Exemplos `curl`

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

### Autenticação e JWT

- Header: `Authorization: Bearer <token>`.
- Assinatura: HS256; payload inclui `sub` (id do usuário), `email`, `plan`, `iat`, `exp`.
- Expiração padrão: 3600s (1 hora).

### Códigos de erro (resumo)

- 200 OK: operação bem-sucedida.
- 401 Unauthorized: token ausente/inválido/expirado (ou login inválido).
- 403 Forbidden: usuário tentando acessar/modificar outro `{id}`.
- 404 Not Found: recurso inexistente (ex.: usuário).
- 405 Method Not Allowed: método HTTP incorreto para a rota.
- 422 Unprocessable Entity: JSON inválido/campos obrigatórios ausentes ou regra de negócio violada.
- 500 Internal Server Error: erro inesperado; mensagem genérica (sem stack trace).

### AWS RDS (MySQL) — Passo a passo

1. Criar instância RDS MySQL
   - Console AWS → RDS → Create database → MySQL 8.x
   - Template: Free tier (se disponível)
   - DB instance identifier: `capitalia-mysql`
   - Defina master username/password
   - VPC default
   - Public access: Yes (ambiente de testes)
   - Security Group: permita Inbound TCP 3306 somente do seu IP
   - Crie e aguarde status `Available`

2. Obter endpoint
   - Em Databases → selecione a instância → copie Endpoint e Port (3306)

3. Criar database lógico e usuário

   ```sql
   mysql -h <ENDPOINT> -P 3306 -u <MASTER_USER> -p
   CREATE DATABASE capitalia CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci;
   CREATE USER 'capitalia_user'@'%' IDENTIFIED BY '<senha-forte>';
   GRANT ALL PRIVILEGES ON capitalia.* TO 'capitalia_user'@'%';
   FLUSH PRIVILEGES;
   ```

4. Aplicar DDL e seed
   - Rode `capitalia/scripts/init_mysql.sql` e `capitalia/scripts/seed_mysql.sql` no DB `capitalia`.

5. Configurar o microsserviço

   ```bash
   export DB_KIND=mysql
   export MYSQL_HOST=<endpoint RDS>
   export MYSQL_USER=capitalia_user
   export MYSQL_PASSWORD=<senha>
   export MYSQL_DB=capitalia
   export JWT_SECRET=<segredo forte>
   pip install -r capitalia/requirements.txt
   python -m capitalia.main
   ```

### Testes

Execute:

```bash
python -m unittest discover -s tests -p 'test_*.py'
```

---

## Diagrama — Ports & Adapters

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
