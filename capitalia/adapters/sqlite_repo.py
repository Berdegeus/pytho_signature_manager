from __future__ import annotations

import sqlite3
from datetime import date
from typing import Optional

from ..domain.models import User
from ..ports.repositories import UserRepository


def _to_entity(row) -> User:
    # row can be tuple or sqlite3.Row depending on connection config
    if row is None:
        return None
    if isinstance(row, sqlite3.Row):
        d = dict(row)
    else:
        cols = [
            "id",
            "name",
            "email",
            "password_hash",
            "salt",
            "plan",
            "start_date",
            "status",
        ]
        d = {k: row[i] for i, k in enumerate(cols)}
    sd = date.fromisoformat(d["start_date"]) if isinstance(d["start_date"], str) else d["start_date"]
    return User(
        id=int(d["id"]) if d["id"] is not None else None,
        name=d["name"],
        email=d["email"],
        password_hash=d["password_hash"],
        salt=d["salt"],
        plan=d["plan"],
        start_date=sd,
        status=d["status"],
    )


class SqliteUserRepository(UserRepository):
    def __init__(self, conn: sqlite3.Connection) -> None:
        self.conn = conn

    def get_by_id(self, user_id: int) -> Optional[User]:
        cur = self.conn.execute(
            """
            SELECT id, name, email, password_hash, salt, plan, start_date, status
            FROM users WHERE id = ?
            """,
            (user_id,),
        )
        row = cur.fetchone()
        return _to_entity(row)

    def get_by_email(self, email: str) -> Optional[User]:
        cur = self.conn.execute(
            """
            SELECT id, name, email, password_hash, salt, plan, start_date, status
            FROM users WHERE email = ?
            """,
            (email,),
        )
        return _to_entity(cur.fetchone())

    def add(self, user: User) -> int:
        cur = self.conn.execute(
            """
            INSERT INTO users (name, email, password_hash, salt, plan, start_date, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user.name,
                user.email,
                user.password_hash,
                user.salt,
                user.plan,
                user.start_date.isoformat(),
                user.status,
            ),
        )
        return int(cur.lastrowid)

    def save(self, user: User) -> None:
        self.conn.execute(
            """
            UPDATE users
            SET name=?, email=?, password_hash=?, salt=?, plan=?, start_date=?, status=?
            WHERE id=?
            """,
            (
                user.name,
                user.email,
                user.password_hash,
                user.salt,
                user.plan,
                user.start_date.isoformat(),
                user.status,
                user.id,
            ),
        )
