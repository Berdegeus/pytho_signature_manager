from __future__ import annotations

from typing import Any, Callable

from ..ports.unit_of_work import UnitOfWork


class SqlUnitOfWork(UnitOfWork):
    def __init__(self, conn_factory: Callable[[], Any], repo_factory: Callable[[Any], Any]):
        self._conn_factory = conn_factory
        self._repo_factory = repo_factory
        self.conn = None
        self.users = None

    def __enter__(self):
        self.conn = self._conn_factory()
        self.begin()
        self.users = self._repo_factory(self.conn)
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if exc:
                self.rollback()
            else:
                self.commit()
        finally:
            try:
                if self.conn is not None:
                    self.conn.close()
            finally:
                self.conn = None
                self.users = None

    def begin(self) -> None:
        # compatible with sqlite and mysql
        cur = self.conn.cursor()
        cur.execute("BEGIN")
        cur.close()

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

