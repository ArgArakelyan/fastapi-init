"""
Настройка подключения к базе, конфигурация драйвера
"""

import logging
from asyncio import wait_for
from contextlib import asynccontextmanager
from typing import AsyncGenerator, Optional

from sqlalchemy import text
from sqlalchemy.engine.url import make_url
from sqlalchemy.ext.asyncio import (AsyncEngine, AsyncSession,
                                    async_sessionmaker, create_async_engine)
from sqlalchemy.orm import DeclarativeBase

from tiny.core.config import config

logger = logging.getLogger(__name__)


class DbManager:
    def __init__(
        self,
        dsn: str,
        pool_size: int = 10,
        pool_timeout: int = 60,
        max_overflow: int = 0,
        pool_pre_ping: bool = True,
        pool_recycle: int = 1800,
        echo: bool = False,
        statement_timeout_ms: int = 2000,
        lock_timeout_ms: int = 1000,
        idle_in_tx_timeout_ms: int = 60000,
        application_name: Optional[str] = config.app.name,
    ):
        self.dsn = dsn
        self.statement_timeout_ms = statement_timeout_ms
        self.lock_timeout_ms = lock_timeout_ms
        self.pool_size = pool_size
        self.pool_timeout = pool_timeout
        self.echo = echo
        self.pool_recycle = pool_recycle
        self.max_overflow = max_overflow
        self.pool_pre_ping = pool_pre_ping
        self.idle_in_tx_timeout_ms = idle_in_tx_timeout_ms
        self.application_name = application_name
        self._url = make_url(self.dsn)
        self.connect_args = {
            "timeout": 5,
            "server_settings": {
                "statement_timeout": str(self.statement_timeout_ms),
                "lock_timeout": str(self.lock_timeout_ms),
                "idle_in_transaction_session_timeout": str(self.idle_in_tx_timeout_ms),
                "application_name": self.application_name,
            },
        }
        self._engine_options = {
            "pool_timeout": self.pool_timeout,
            "pool_recycle": self.pool_recycle,
            "pool_size": self.pool_size,
            "max_overflow": self.max_overflow,
            "pool_pre_ping": self.pool_pre_ping,
            "echo": self.echo,
            "connect_args": self.connect_args,
        }
        self._engine: Optional[AsyncEngine] = None
        self._sessionmaker: Optional[async_sessionmaker[AsyncSession]] = None

    async def init(self):
        self._ensure_engine()
        try:
            await self.check_alive_db()
            logger.info(
                "Postgres connection successfully",
                extra={
                    "pool_size": self.pool_size,
                    "application_name": self.application_name,
                },
            )
        except Exception as e:
            logger.error("Postgres connection failed", extra={"error": str(e)})
            raise

    def _ensure_engine(self) -> None:
        if self._engine is None:
            self._engine = create_async_engine(self._url, **self._engine_options)
            self._sessionmaker = async_sessionmaker(
                self._engine,
                class_=AsyncSession,
                autoflush=False,
                expire_on_commit=False,
            )

    @property
    def engine(self) -> AsyncEngine:
        self._ensure_engine()
        assert self._engine is not None
        return self._engine

    @property
    def sessionmaker(self) -> async_sessionmaker[AsyncSession]:
        self._ensure_engine()
        assert self._sessionmaker is not None
        return self._sessionmaker

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Контекст для краткоживущих сессий (per-request/per-job).
        Делает rollback при исключениях и гарантирует закрытие.
        """
        async with self.sessionmaker() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    @asynccontextmanager
    async def transaction(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Удобный контекст для транзакции:
        begin/commit при успехе, rollback при ошибке.
        """
        async with self.sessionmaker() as session:
            try:
                async with session.begin():
                    yield session
            except Exception:
                # session.begin контекст сам делает rollback, но явный rollback не повредит
                await session.rollback()
                raise
            finally:
                await session.close()

    async def check_alive_db(self, timeout: float = 0.5):
        if self._engine is None:
            raise RuntimeError("DB Engine is not initializated")

        async def _probe():
            async with self._engine.connect() as conn:
                await conn.execute(text("SELECT 1"))

        await wait_for(_probe(), timeout=timeout)

    async def dispose(self) -> None:
        """
        Корректно закрывает пул соединений (например, на shutdown приложения).
        """
        if self._engine is not None:
            await self._engine.dispose()
            self._engine = None
            self._sessionmaker = None


db = DbManager(
    dsn=config.database.SQLALCHEMY_DATABASE_URI, pool_size=config.database.pool_size
)


class Base(DeclarativeBase):
    pass
