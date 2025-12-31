from contextlib import asynccontextmanager

from tiny.core.database import db
from tiny.core.redis import redis_manager


@asynccontextmanager
async def lifespan(_):
    await db.init()
    await redis_manager.connect()
    try:
        yield
    finally:
        await redis_manager.disconnect()
        await db.dispose()
