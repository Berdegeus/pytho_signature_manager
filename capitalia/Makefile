PY?=python3

.PHONY: run_sqlite run_mysql init_sqlite seed_sqlite test

init_sqlite:
	$(PY) -m capitalia.scripts.init_sqlite

seed_sqlite:
	$(PY) -m capitalia.scripts.seed_sqlite

run_sqlite:
	DB_KIND=sqlite SQLITE_PATH=$${SQLITE_PATH:-capitalia.db} JWT_SECRET=$${JWT_SECRET:-local-dev-secret} PORT=$${PORT:-8080} \
	$(PY) -m capitalia.main

run_mysql:
	DB_KIND=mysql MYSQL_HOST=$${MYSQL_HOST:-localhost} MYSQL_USER=$${MYSQL_USER:-capitalia_user} \
	MYSQL_PASSWORD=$${MYSQL_PASSWORD:-changeme} MYSQL_DB=$${MYSQL_DB:-capitalia} \
	JWT_SECRET=$${JWT_SECRET:-local-dev-secret} PORT=$${PORT:-8080} \
	$(PY) -m capitalia.main

test:
	$(PY) -m unittest discover -s tests -p 'test_*.py'

# Optional helpers (require `mysql` CLI installed)
.PHONY: init_mysql seed_mysql
init_mysql:
	@echo "Applying DDL to MySQL...";
	MYSQL_PORT=$${MYSQL_PORT:-3306}; \
	mysql -h $${MYSQL_HOST:-localhost} -P $$MYSQL_PORT -u $${MYSQL_USER:-capitalia_user} -p$${MYSQL_PASSWORD:-changeme} \
	$${MYSQL_DB:-capitalia} < capitalia/scripts/init_mysql.sql

seed_mysql:
	@echo "Seeding MySQL...";
	MYSQL_PORT=$${MYSQL_PORT:-3306}; \
	mysql -h $${MYSQL_HOST:-localhost} -P $$MYSQL_PORT -u $${MYSQL_USER:-capitalia_user} -p$${MYSQL_PASSWORD:-changeme} \
	$${MYSQL_DB:-capitalia} < capitalia/scripts/seed_mysql.sql
