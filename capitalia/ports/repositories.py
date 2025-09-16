from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from ..domain.models import User


class UserRepository(ABC):
    @abstractmethod
    def get_by_id(self, user_id: int) -> Optional[User]:
        ...

    @abstractmethod
    def get_by_email(self, email: str) -> Optional[User]:
        ...

    @abstractmethod
    def add(self, user: User) -> int:
        ...

    @abstractmethod
    def save(self, user: User) -> None:
        ...
