# Python Signature Manager - Docker Setup

Este documento explica como executar o projeto Python Signature Manager usando Docker.

## Arquivos Docker

- `Dockerfile`: Define a imagem Docker da aplicação
- `docker-compose.yml`: Configuração para execução com Docker Compose
- `.dockerignore`: Arquivos ignorados durante o build
- `.env.example`: Exemplo de configuração de variáveis de ambiente

## Como usar

### 1. Usando Docker Compose (Recomendado)

```bash
# 1. Clone o repositório e navegue até o diretório
cd python_signature_manager

# 2. Copie e configure as variáveis de ambiente
cp .env.example .env
# Edite o arquivo .env com suas configurações

# 3. Execute a aplicação
docker-compose up -d

# 4. Verifique os logs
docker-compose logs -f

# 5. Para parar a aplicação
docker-compose down
```

### 2. Usando Docker diretamente

```bash
# 1. Construir a imagem
docker build -t python-signature-manager .

# 2. Criar diretório para dados
mkdir -p data

# 3. Executar o container
docker run -d \
  --name signature-manager \
  -p 8080:8080 \
  -e DB_KIND=sqlite \
  -e SQLITE_PATH=/app/data/capitalia.db \
  -e JWT_SECRET=your-secret-here \
  -v $(pwd)/data:/app/data \
  python-signature-manager

# 4. Verificar logs
docker logs signature-manager

# 5. Parar o container
docker stop signature-manager
docker rm signature-manager
```

## Configurações

### Variáveis de Ambiente

- `DB_KIND`: Tipo de banco (`sqlite` ou `mysql`)
- `SQLITE_PATH`: Caminho para o banco SQLite (se usar SQLite)
- `MYSQL_HOST`: Host do MySQL (se usar MySQL)
- `MYSQL_USER`: Usuário do MySQL
- `MYSQL_PASSWORD`: Senha do MySQL
- `MYSQL_DB`: Nome do banco MySQL
- `MYSQL_PORT`: Porta do MySQL
- `JWT_SECRET`: Chave secreta para JWT
- `PORT`: Porta da aplicação (padrão: 8080)

### Usando MySQL

Para usar MySQL, descomente as seções correspondentes no `docker-compose.yml` e configure as variáveis de ambiente adequadamente.

## Portas

- A aplicação é exposta na porta `8080`
- O MySQL (se habilitado) é exposto na porta `3306`

## Volumes

- `./data:/app/data`: Armazena o banco de dados SQLite

## Health Check

O container inclui um health check que verifica se a aplicação está respondendo.

## Segurança

- A aplicação executa como usuário não-root (`appuser`)
- Use senhas fortes em produção
- Configure adequadamente as variáveis de ambiente

## Troubleshooting

```bash
# Ver logs detalhados
docker-compose logs -f app

# Executar comandos dentro do container
docker-compose exec app bash

# Reconstruir a imagem
docker-compose build --no-cache
```
