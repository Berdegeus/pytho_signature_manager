from __future__ import annotations

from datetime import date
from typing import Optional, Any

from ..domain.models import User
from ..ports.repositories import UserRepository


def _to_entity(row: Optional[dict]) -> Optional[User]:
    if not row:
        return None
    sd = row["start_date"]
    if isinstance(sd, (bytes, bytearray)):
        sd = sd.decode()
    if isinstance(sd, str):
        sd = date.fromisoformat(sd)
    # PyMySQL DictCursor returns dict with correct types (DATE -> date)
    return User(
        id=int(row["id"]) if row.get("id") is not None else None,
        name=row["name"],
        email=row["email"],
        password_hash=row["password_hash"],
        salt=row["salt"],
        plan=row["plan"],
        start_date=sd,
        status=row["status"],
    )


class MySQLUserRepository(UserRepository):
    def __init__(self, conn: Any) -> None:
        self.conn = conn

    def get_by_id(self, user_id: int) -> Optional[User]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, email, password_hash, salt, plan, start_date, status
                FROM users WHERE id=%s
                """,
                (user_id,),
            )
            row = cur.fetchone()
            return _to_entity(row)

    def get_by_email(self, email: str) -> Optional[User]:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, name, email, password_hash, salt, plan, start_date, status
                FROM users WHERE email=%s
                """,
                (email,),
            )
            return _to_entity(cur.fetchone())

    def add(self, user: User) -> int:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO users (name, email, password_hash, salt, plan, start_date, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user.name,
                    user.email,
                    user.password_hash,
                    user.salt,
                    user.plan,
                    user.start_date,
                    user.status,
                ),
            )
            return int(cur.lastrowid or cur.connection.insert_id())

    def save(self, user: User) -> None:
        with self.conn.cursor() as cur:
            cur.execute(
                """
                UPDATE users
                SET name=%s, email=%s, password_hash=%s, salt=%s, plan=%s, start_date=%s, status=%s
                WHERE id=%s
                """,
                (
                    user.name,
                    user.email,
                    user.password_hash,
                    user.salt,
                    user.plan,
                    user.start_date,
                    user.status,
                    user.id,
                ),
            )
