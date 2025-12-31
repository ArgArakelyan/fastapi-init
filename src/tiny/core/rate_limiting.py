import logging
from functools import wraps
from typing import Callable

from fastapi import Request
from prometheus_client import Counter
from slowapi import _rate_limit_exceeded_handler  # noqa
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from tiny.core.config import config
from tiny.core.metrics import registry

logger = logging.getLogger(__name__)

RATE_LIMITS = {
    "auth_login": "10/minute",  # OAuth loggin attempts
    "auth_refresh": "3/minute",  # Token refresh attempts
    "account_refresh": "20/minute",  # Account info refresh attempts
    "account_delete": "3/hour",  # Account deletion attempts
}


class RateLimiter:
    def __init__(self):
        self.redis_storage_uri = config.redis.REDIS_URI
        self.redis_key_prefix = "rl:"
        self._limiter = Limiter(
            key_func=self.get_rate_limit_key,
            storage_uri=self.redis_storage_uri,
            enabled=True,
            key_prefix=config.redis.cache_prefix
        )

    @staticmethod
    def get_rate_limit_key(request: Request):
        try:
            auth_header = request.headers.get("authorization")
            if auth_header and auth_header.startswith("Bearer "):
                pass
        except Exception as e:
            logger.debug(f"Failed to extract user from token: {e}")

        try:
            if hasattr(request, "client") and hasattr(request.client, "host"):
                return request.client.host
            else:
                return get_remote_address(request)
        except Exception as e:
            logger.warning(f"Failed to get remote address for rate limiting: {e}")
            # Ultimate fallback
            return "unknown"

    def limit(self, rate_limit_str: str) -> Callable:
        """
        Декоратор для ограничения запросов
        """

        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                return await func(*args, **kwargs)

            # Применяем лимитер из slowapi
            return self._limiter.limit(rate_limit_str)(wrapper)

        return decorator


rl_blocked_total = Counter(
    "http_rate_limit_blocked_total",
    "Requests blocked by rate limiting",
    ["route", "method"],
    registry=registry,
)


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded):
    route = getattr(request.scope.get("route"), "path", "unknown")
    rl_blocked_total.labels(route=route, method=request.method).inc()
    return _rate_limit_exceeded_handler(request, exc)


rate_limiter = RateLimiter()


def auth_rate_limit(endpoint_type: str = "auth_login") -> Callable:
    """
    Декоратор для ограничения запросов к аутентификации
    """
    return rate_limiter.limit(RATE_LIMITS.get(endpoint_type, "10/minute"))


def rate_limit(limit_str: str) -> Callable:
    """
    Универсальный декоратор для rate limiting
    """
    return rate_limiter.limit(limit_str)
