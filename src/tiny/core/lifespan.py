from contextlib import asynccontextmanager
import threading
from prometheus_client import start_http_server
from tiny.core.metrics import registry
from tiny.core.config import config
from tiny.core.database import db
from tiny.core.redis import redis_manager


@asynccontextmanager
async def lifespan(_):
    prometheus_thread = threading.Thread(
        target=start_http_server,
        args=(config.prometheus.metrics_port,),
        kwargs={"registry": registry},
        daemon=True,
        name="prometheus-metrics-server",
    )
    prometheus_thread.start()

    await db.init()
    await redis_manager.connect()
    try:
        yield
    finally:
        await redis_manager.disconnect()
        await db.dispose()
