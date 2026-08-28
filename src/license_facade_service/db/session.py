from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker


@dataclass
class Database:
    engine: Engine
    session_factory: sessionmaker[Session]

    @classmethod
    def from_url(cls, database_url: str) -> "Database":
        engine = create_engine(database_url, future=True, pool_pre_ping=True)
        factory = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, future=True)
        return cls(engine=engine, session_factory=factory)

    @contextmanager
    def transaction(self):
        session = self.session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def close(self) -> None:
        self.engine.dispose()
