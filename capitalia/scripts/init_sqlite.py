from __future__ import annotations

import os
import sqlite3
from pathlib import Path

# Local import via package path
from ..config import Config


DDL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    plan TEXT NOT NULL CHECK(plan IN ('basic','trial','premium')) DEFAULT 'trial',
    start_date TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active','suspended','expired')) DEFAULT 'active',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER IF NOT EXISTS users_updated_at
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
  UPDATE users SET updated_at = CURRENT_TIMESTAMP WHERE id = OLD.id;
END;
"""


def main() -> None:
    cfg = Config()
    path = Path(cfg.sqlite_path)
    print(f"[sqlite] initializing at {path}")
    with sqlite3.connect(path) as conn:
        conn.executescript(DDL)
    print("[sqlite] done")


if __name__ == "__main__":
    main()
