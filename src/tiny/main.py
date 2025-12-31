from fastapi import FastAPI
from prometheus_client import start_http_server
from slowapi.errors import RateLimitExceeded

from tiny.api import api_router
from tiny.core.config import config, fastapi_settings
from tiny.core.lifespan import lifespan
from tiny.core.log import setup_logging
from tiny.core.metrics import registry
from tiny.core.rate_limiting import rate_limit_exceeded_handler, rate_limiter
from tiny.middlewares.security import SecurityMiddleware

setup_logging()
app = FastAPI(**fastapi_settings, lifespan=lifespan)

app.include_router(api_router)

app.add_middleware(SecurityMiddleware)

app.state.limiter = rate_limiter._limiter  # noqa

app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

start_http_server(config.prometheus.metrics_port, registry=registry)
