from __future__ import annotations

from datetime import date
from typing import Optional

from ..domain.models import User
from ..domain.errors import NotFoundError, ValidationError
from ..ports.unit_of_work import UnitOfWork
from ..ports.clock import Clock


class SubscriptionService:
    """Casos de uso com transação por operação (UoW)."""

    def __init__(self, uow_factory, clock: Clock):
        self._uow_factory = uow_factory
        self._clock = clock

    def _get_user(self, uow: UnitOfWork, user_id: int) -> User:
        user = uow.users.get_by_id(user_id)
        if not user:
            raise NotFoundError("user not found")
        return user

    def read_effective_status(self, user_id: int) -> dict:
        today = self._clock.today()
        with self._uow_factory() as uow:
            user = self._get_user(uow, user_id)
            effective = user.evaluate_status(today)
            if effective != user.status:
                user.status = effective
                uow.users.save(user)
                uow.commit()
            return {"user_id": user.id, "plan": user.plan, "status": effective}

    def upgrade(self, user_id: int) -> dict:
        with self._uow_factory() as uow:
            user = self._get_user(uow, user_id)
            if user.plan not in ("basic", "trial"):
                raise ValidationError("only basic|trial can upgrade to premium")
            user.plan = "premium"
            user.status = "active"
            uow.users.save(user)
            uow.commit()
            return {"user_id": user.id, "plan": user.plan, "status": user.status}

    def downgrade(self, user_id: int) -> dict:
        with self._uow_factory() as uow:
            user = self._get_user(uow, user_id)
            if user.plan != "premium":
                raise ValidationError("only premium can downgrade to basic")
            user.plan = "basic"
            user.status = "active"
            uow.users.save(user)
            uow.commit()
            return {"user_id": user.id, "plan": user.plan, "status": user.status}

    def suspend(self, user_id: int) -> dict:
        with self._uow_factory() as uow:
            user = self._get_user(uow, user_id)
            if user.plan != "premium":
                raise ValidationError("only premium can be suspended")
            user.status = "suspended"
            uow.users.save(user)
            uow.commit()
            return {"user_id": user.id, "plan": user.plan, "status": user.status}

    def reactivate(self, user_id: int) -> dict:
        with self._uow_factory() as uow:
            user = self._get_user(uow, user_id)
            if user.plan != "premium" or user.status != "suspended":
                raise ValidationError("only suspended premium can reactivate")
            user.status = "active"
            uow.users.save(user)
            uow.commit()
            return {"user_id": user.id, "plan": user.plan, "status": user.status}
