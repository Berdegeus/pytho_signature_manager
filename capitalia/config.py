import os
import pathlib
from typing import Callable, Any, Dict


def _load_dotenv_if_present() -> None:
    # Optional, no dependency: load simple KEY=VALUE lines
    env_path = pathlib.Path(__file__).parent / ".env"
    if env_path.exists():
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip())


_load_dotenv_if_present()


class Config:
    def __init__(self) -> None:
        self.db_kind: str = os.environ.get('DB_KIND', 'sqlite').lower()
        self.sqlite_path: str = os.environ.get('SQLITE_PATH', 'capitalia.db')
        self.mysql: Dict[str, str] = {
            'host': os.environ.get('MYSQL_HOST', 'localhost'),
            'user': os.environ.get('MYSQL_USER', 'capitalia_user'),
            'password': os.environ.get('MYSQL_PASSWORD', 'changeme'),
            'db': os.environ.get('MYSQL_DB', 'capitalia'),
            'port': int(os.environ.get('MYSQL_PORT', '3306')),
            'charset': 'utf8mb4',
        }
        self.jwt_secret: str = os.environ.get('JWT_SECRET', 'change-me')
        self.port: int = int(os.environ.get('PORT', '8080'))

    def get_strategy(self) -> str:
        if self.db_kind not in ('sqlite', 'mysql'):
            raise ValueError('DB_KIND must be sqlite or mysql')
        return self.db_kind

    def get_connection_factory(self) -> Callable[[], Any]:
        kind = self.get_strategy()
        if kind == 'sqlite':
            import sqlite3

            path = self.sqlite_path

            def factory() -> sqlite3.Connection:
                conn = sqlite3.connect(path)
                conn.execute('PRAGMA foreign_keys = ON')
                return conn

            return factory
        else:
            import pymysql

            def factory() -> Any:
                return pymysql.connect(
                    host=self.mysql['host'],
                    user=self.mysql['user'],
                    password=self.mysql['password'],
                    database=self.mysql['db'],
                    port=self.mysql['port'],
                    charset=self.mysql['charset'],
                    cursorclass=pymysql.cursors.DictCursor,
                    autocommit=False,
                )

            return factory

    def get_repo_factory(self) -> Callable[[Any], Any]:
        kind = self.get_strategy()
        if kind == 'sqlite':
            from .adapters.sqlite_repo import SqliteUserRepository

            def repo_factory(conn: Any) -> Any:
                return SqliteUserRepository(conn)

            return repo_factory
        else:
            from .adapters.mysql_repo import MySQLUserRepository

            def repo_factory(conn: Any) -> Any:
                return MySQLUserRepository(conn)

            return repo_factory

