from __future__ import annotations

import unittest
from datetime import date, timedelta

from capitalia.domain.models import User
from capitalia.domain.services import SubscriptionService
from capitalia.ports.clock import Clock


class FakeClock(Clock):
    def __init__(self, today: date) -> None:
        self._today = today

    def today(self) -> date:
        return self._today


class FakeRepo:
    def __init__(self, users):
        self._by_id = {u.id: u for u in users}

    def get_by_id(self, user_id):
        return self._by_id.get(user_id)

    def get_by_email(self, email):  # not used here
        for u in self._by_id.values():
            if u.email == email:
                return u
        return None

    def add(self, user):  # not used here
        self._by_id[user.id] = user
        return user.id

    def save(self, user):
        self._by_id[user.id] = user


class FakeUoW:
    def __init__(self, repo: FakeRepo):
        self.repo = repo
        self.committed = False
        self.users = None

    def __enter__(self):
        self.users = self.repo
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def begin(self):
        pass

    def commit(self):
        self.committed = True

    def rollback(self):
        pass


def make_service(uow):
    return SubscriptionService(lambda: uow, FakeClock(date.today()))


class TestDomain(unittest.TestCase):
    def test_trial_expires_after_30_days(self):
        u = User(1, "A", "a@a", "h", "s", "trial", date.today() - timedelta(days=31), "active")
        self.assertEqual(u.evaluate_status(date.today()), "expired")

    def test_basic_always_active(self):
        u = User(1, "A", "a@a", "h", "s", "basic", date.today(), "expired")
        self.assertEqual(u.evaluate_status(date.today()), "active")

    def test_upgrade_and_downgrade(self):
        u = User(1, "A", "a@a", "h", "s", "trial", date.today(), "active")
        repo = FakeRepo([u])
        svc = make_service(FakeUoW(repo))
        r = svc.upgrade(1)
        self.assertEqual(r["plan"], "premium")
        self.assertEqual(r["status"], "active")
        r2 = svc.downgrade(1)
        self.assertEqual(r2["plan"], "basic")
        self.assertEqual(r2["status"], "active")

    def test_suspend_and_reactivate(self):
        u = User(1, "A", "a@a", "h", "s", "premium", date.today(), "active")
        repo = FakeRepo([u])
        svc = make_service(FakeUoW(repo))
        r = svc.suspend(1)
        self.assertEqual(r["status"], "suspended")
        r2 = svc.reactivate(1)
        self.assertEqual(r2["status"], "active")

    def test_read_effective_status_updates_persistence(self):
        # trial started 40 days ago -> expired and persisted
        start = date.today() - timedelta(days=40)
        u = User(1, "A", "a@a", "h", "s", "trial", start, "active")
        repo = FakeRepo([u])
        uow = FakeUoW(repo)
        svc = SubscriptionService(lambda: uow, FakeClock(date.today()))
        r = svc.read_effective_status(1)
        self.assertEqual(r["status"], "expired")
        self.assertEqual(repo.get_by_id(1).status, "expired")


if __name__ == "__main__":
    unittest.main()

