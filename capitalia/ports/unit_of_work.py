from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class UnitOfWork(ABC):
    users: Any

    def __enter__(self) -> "UnitOfWork":  # pragma: no cover
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # pragma: no cover
        if exc:
            self.rollback()
        else:
            self.commit()

    @abstractmethod
    def begin(self) -> None:
        ...

    @abstractmethod
    def commit(self) -> None:
        ...

    @abstractmethod
    def rollback(self) -> None:
        ...

