import uuid
from contextvars import ContextVar

import structlog
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

request_id_var: ContextVar[str] = ContextVar("request_id", default="no-request")


class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = request_id
        token = request_id_var.set(request_id)

        structlog.contextvars.bind_contextvars(request_id=request_id)
        structlog.contextvars.bind_contextvars(
            client_ip=request.client.host if request.client else None,
            method=request.method,
            path=str(request.url.path),
        )

        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        request_id_var.reset(token)
        structlog.contextvars.clear_contextvars()  # Очистка
        return response
