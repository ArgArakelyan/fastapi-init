import logging
from typing import Optional

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import (BaseHTTPMiddleware,
                                       RequestResponseEndpoint)

logger = logging.getLogger(__name__)

DEFAULT_ALLOWED_METHODS = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]


class SecurityMiddleware(BaseHTTPMiddleware):
    """Middleware обрабатывает все входящие запросы и добавляет уровень безопасности
    перед их обработкой основным приложением.

    Выполняет следующее:
    1 - проверка размера запроса (ограничение до 10MiB)
    2 - Валидация http методов (разрешает только стандартные методы)
    3 - Добавляет нужные загаловки к ответам (для безопасности)
    4 - Обработка исключений с возвратом безопасных ошибок
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """

        :arg
            request (Request): Объект HTTP-запроса
            call_next (RequestResponseEndpoint): Следующий обработчик в цепочке middleware

        :returns:
            Response: HTTP-ответ с примененными политиками безопасности

        :raises:
            Возвращает JSONResponse с кодом ошибки вместо выбрасывания исключений:
            - 413: Если превышен максимальный размер запроса (10MB)
            - 400: Если неверный формат Content-Length
            - 405: Если используется неразрешенный HTTP-метод
            - 500: При внутренних ошибках middleware
        """
        try:
            if request.method == "OPTIONS":
                response = await call_next(request)
                return response

            # request size validation
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    content_length_int = int(content_length)
                    if not validate_request_size(content_length_int):
                        logger.warning(
                            f"Request too large: {content_length} bytes from {request.client.host}"
                        )
                        return JSONResponse(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            content={
                                "error": "request_too_large",
                                "detail": "Request size exceeds maximum allowed limit",
                                "max_size": "10MB",
                            },
                        )
                except ValueError:
                    logger.warning(
                        f"Invalid Content-Length header",
                        extra={
                            "request": {
                                "content_length": content_length,
                                "from": request.client.host,
                            }
                        },
                    )
                    return JSONResponse(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        content={
                            "error": "invalid_content_length",
                            "detail": "Invalid Content-Length header",
                        },
                    )

            # request method validation
            if request.method not in DEFAULT_ALLOWED_METHODS:
                logger.warning(
                    f"Invalid HTTP method",
                    extra={
                        "request": {
                            "method": request.method,
                            "from": request.client.host,
                        }
                    },
                )
                return JSONResponse(
                    status_code=status.HTTP_405_METHOD_NOT_ALLOWED,
                    content={
                        "error": "method_not_allowed",
                        "detail": f"HTTP method {request.method} not allowed",
                    },
                )

            # process the request
            response = await call_next(request)

            self.add_security_headers(response, request)
            return response
        except Exception as e:
            logger.error("Security middleware error", exc_info=e)

            return JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={
                    "error": "internal_server_error",
                    "detail": "An internal error occurred",
                },
                headers={
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                },
            )

    @staticmethod
    def add_security_headers(response: Response, request: Request) -> Response:
        """Добавляет security-заголовки к HTTP-ответу.

        - X-Content-Type-Options: nosniff - предотвращает MIME-sniffing
        - X-Frame-Options: DENY - запрещает встраивание в iframe
        - X-XSS-Protection: 1; mode=block - включает защиту от XSS в браузере
        - Referrer-Policy: same-origin - ограничивает передачу Referer

        :arg
            response (Response): Объект HTTP-ответа
            request (Request): Объект HTTP-запроса (не используется, но сохранен для совместимости)

        :returns:
            Response: Ответ с добавленными security-заголовками
        """

        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "X-XSS-Protection": "1; mode=block",
                "Referrer-Policy": "same-origin",
            }
        )

        return response


def is_suspicious_ip(ip: str) -> bool:
    """
    Проверяет, является ли IP-адрес подозрительным

    IP-адреса из приватных диапазонов считаются безопасными
    Все остальные IP-адреса пока считаются безопасными
    """
    # Private/local IPs are generally safe
    private_ranges = ["127.0.0.1", "10.", "192.168.", "172."]

    if any(ip.startswith(range_start) for range_start in private_ranges):
        return False

    # Add your suspicious IP detection logic here
    # For example, check against threat intelligence feeds

    return False


def validate_request_size(content_length: Optional[int] = None) -> bool:
    """Проверяет, не превышает ли размер запроса максимально допустимое значение"""
    MAX_REQUEST_SIZE = 10 * 1024 * 1024  # 10MB # noqa

    if content_length and content_length > MAX_REQUEST_SIZE:
        logger.warning(f"Request size too large: {content_length} bytes")
        return False

    return True
