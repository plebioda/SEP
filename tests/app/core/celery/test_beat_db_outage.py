# Copyright (C) 2026 Percona LLC
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Define tests for Celery beat riding out an outage of its schedule database.

Celery's beat service exits on any exception from ``tick()``, and dev mode's
``--start-celery`` does not restart it. ``DatabaseScheduler`` reads the database
on every tick through its ``schedule`` property, so an outage of PMM's
PostgreSQL, such as a PMM Server restart, must not raise out of it.
"""

import shutil
from pathlib import Path

from celery import Celery
from sqlalchemy_celery_beat.schedulers import DatabaseScheduler


def test_beat_keeps_its_schedule_while_the_database_is_down(tmp_path: Path) -> None:
    """Keep ticking on the schedule already loaded while the database is down.

    sqlalchemy-celery-beat 0.8.4 raised ``OperationalError`` here, and beat exited.

    :param tmp_path: The per-test temporary directory.
    """
    store = tmp_path / "store"
    store.mkdir()
    scheduler = DatabaseScheduler(
        app=Celery("test", set_as_current=False),
        dburi=f"sqlite:///{store / 'schedule.db'}",
    )
    loaded = dict(scheduler.schedule)
    assert loaded
    scheduler.tick()

    scheduler.engine.dispose()
    shutil.rmtree(store)

    for _ in range(2):
        assert scheduler.tick() > 0
        assert scheduler.schedule.keys() == loaded.keys()
