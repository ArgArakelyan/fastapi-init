import logging
from abc import ABC
from typing import Dict, Optional

import httpx
from tenacity import (before_sleep_log, retry, retry_if_exception,
                      stop_after_attempt, wait_exponential)

logger = logging.getLogger(__name__)


def _is_retryable_httpx_exc(exc: BaseException) -> bool:
    # Network/timeouts are always retryable
    if isinstance(
        exc, (httpx.TimeoutException, httpx.ConnectError, httpx.NetworkError)
    ):
        return True

    # Retry only selected HTTP status codes
    if isinstance(exc, httpx.HTTPStatusError) and exc.response is not None:
        code = exc.response.status_code
        return (500 <= code < 600) or (code == 429)

    return False


class BaseClient(ABC):
    def __init__(
        self, base_url: str, headers: Optional[Dict[str, str]] = None, timeout: int = 15
    ) -> None:
        self.base_url = base_url
        self.headers = headers or {}
        self.timeout = timeout
        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            headers=self.headers,
            timeout=self.timeout,
            limits=httpx.Limits(max_keepalive_connections=15, max_connections=30),
        )

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=3),
        retry=retry_if_exception(_is_retryable_httpx_exc),
        before_sleep=before_sleep_log(logger, logging.WARNING),
        reraise=True,
    )
    async def request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        if self._client is None:
            raise RuntimeError("HTTP Client not initialized")
        response = await self._client.request(method, endpoint, **kwargs)

        response.raise_for_status()
        return response.json()

    async def close(self) -> None:
        await self._client.aclose()
