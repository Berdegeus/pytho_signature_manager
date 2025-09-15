# Use uma imagem oficial do Python como base
FROM python:3.11-slim as base

# Definir variáveis de ambiente
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Criar um usuário não-root para segurança
RUN adduser --disabled-password --gecos '' --shell /bin/bash appuser

# Instalar dependências do sistema se necessário
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Definir diretório de trabalho
WORKDIR /app

# Copiar arquivo de dependências
COPY requirements.txt .

# Instalar dependências Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copiar código da aplicação
COPY . .

# Criar diretório para banco de dados SQLite
RUN mkdir -p /app/data && \
    chown -R appuser:appuser /app

# Mudar para usuário não-root
USER appuser

# Expor porta da aplicação
EXPOSE 8080

# Comando para executar a aplicação
CMD ["python", "-m", "capitalia.main"]
