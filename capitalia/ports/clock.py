from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import date


class Clock(ABC):
    @abstractmethod
    def today(self) -> date:
        ...


class RealClock(Clock):
    def today(self) -> date:
        from datetime import date as _date

        return _date.today()
