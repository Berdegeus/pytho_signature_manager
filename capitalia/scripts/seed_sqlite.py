from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import date, timedelta
from pathlib import Path

from ..config import Config


def seed_user(conn: sqlite3.Connection, name: str, email: str, password: str, plan: str, start_date: date, status: str):
    """Insert or update the user by email (idempotent)."""
    salt = secrets.token_hex(16)
    password_hash = hashlib.sha256((salt + password).encode()).hexdigest()
    conn.execute(
        """
        INSERT INTO users (name, email, password_hash, salt, plan, start_date, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET
            name=excluded.name,
            password_hash=excluded.password_hash,
            salt=excluded.salt,
            plan=excluded.plan,
            start_date=excluded.start_date,
            status=excluded.status
        """,
        (name, email, password_hash, salt, plan, start_date.isoformat(), status),
    )


def main() -> None:
    cfg = Config()
    path = Path(cfg.sqlite_path)
    with sqlite3.connect(path) as conn:
        # Usuário em trial que começou há 40 dias (irá expirar ao consultar status)
        seed_user(
            conn,
            name="Alice",
            email="alice@example.com",
            password="password123",
            plan="trial",
            start_date=date.today() - timedelta(days=40),
            status="active",
        )
        # Usuário premium ativo
        seed_user(
            conn,
            name="Bob",
            email="bob@example.com",
            password="password123",
            plan="premium",
            start_date=date.today(),
            status="active",
        )
    print("[sqlite] seed completed")


if __name__ == "__main__":
    main()
