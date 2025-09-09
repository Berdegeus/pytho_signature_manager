from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Optional


Plan = str  # 'basic' | 'trial' | 'premium'
Status = str  # 'active' | 'suspended' | 'expired'


@dataclass
class User:
    id: Optional[int]
    name: str
    email: str
    password_hash: str
    salt: str
    plan: Plan
    start_date: date
    status: Status

    def evaluate_status(self, today: date) -> Status:
        """
        Regras de status:
        - basic  -> sempre active
        - trial  -> 30 dias desde start_date; após isso expired
        - premium-> respeita status persistido (active/suspended)
        Retorna o status efetivo (pode ser igual ao atual). Não persiste.
        """
        if self.plan == 'basic':
            return 'active'
        if self.plan == 'trial':
            if self.start_date + timedelta(days=30) <= today:
                return 'expired'
            return 'active'
        # premium: mantém status (active ou suspended)
        return self.status

