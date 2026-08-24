from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from snowimpact.core.settings import Settings, get_settings
from snowimpact.db.models import Base


class Database:
    def __init__(self, settings: Settings | None = None):
        self.settings = settings or get_settings()
        kwargs = {"pool_pre_ping": True}
        if self.settings.database_url.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False}
        self.engine = create_engine(self.settings.database_url, **kwargs)
        self.session_factory = sessionmaker(bind=self.engine, expire_on_commit=False)

    def init(self) -> None:
        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
