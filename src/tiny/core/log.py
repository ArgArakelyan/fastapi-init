"""
Logging configuration (json)
"""

import logging
import sys
from contextvars import ContextVar
from pathlib import Path
from typing import Any

import structlog

from tiny.core.config import config

request_id_var: ContextVar[str] = ContextVar("request_id", default="no-request")


def add_request_id(_, __, event_dict):
    """
    Добавляется correlation id (в виде request_id к запросам)

    Получаем request_id из хэдера запроса (или генерируем сами, если отсутствует) - X-Request-Id
    """
    event_dict["request_id"] = request_id_var.get()
    return event_dict


class RequestIDFilter(logging.Filter):
    def filter(self, record):
        # Для uvicorn.access парсим request_id из сообщения или contextvar
        if "request_id" not in record.__dict__:
            record.request_id = request_id_var.get("no-request")
        return True


def sanitize_tokens(
    logger: Any, method: str, event_dict: dict[str, Any] # noqa
) -> dict[str, Any]:  # noqa
    """Удаляет токены из логов для предотвращения утечки credentials"""
    import re

    message = event_dict.get("event", "")

    patterns = [
        (r'(\?|&)(?:token|access_token)=[^\s&"\']+', r"\1token=[REDACTED]"),
        (r"Bearer\s+[A-Za-z0-9\-._~+/]+=*", "Bearer [REDACTED]"),
        (r"eyJ[A-Za-z0-9\-._~+/]+=*", "[REDACTED_JWT]"),
        (
            r'["\']?(?:token|access_token|jwt|refresh_token)["\']?\s*[=:]\s*["\']?[A-Za-z0-9\-._~+/]+=*["\']?',
            "token=[REDACTED]",
        ),
        (r"key=[^&]+", "key=[REDACTED]"),
        (
            r"\{[^\}]*['\"]access_token['\"]:\s*['\"][^'\"]+['\"][^\}]*\}",
            "{access_token:[REDACTED]}",
        )
    ]

    for pattern, replacement in patterns:
        message = re.sub(pattern, replacement, message, flags=re.IGNORECASE)

    event_dict["event"] = message
    return event_dict


def add_caller_info(
    logger: Any, method: str, event_dict: dict[str, Any] # noqa
) -> dict[str, Any]:
    try:
        record = event_dict.get("_record")
        if record:
            pathname = record.pathname
            lineno = record.lineno
            funcname = record.funcName
            logger_name = record.name
        else:
            import sys

            frame = sys._getframe(2)  # noqa
            pathname = frame.f_code.co_filename
            lineno = frame.f_lineno
            funcname = frame.f_code.co_name
            logger_name = None

        try:
            rel_path = Path(pathname).relative_to(Path.cwd())
            file_location = f"{rel_path}:{lineno}"
        except (ValueError, AttributeError):
            file_location = f"{Path(pathname).name}:{lineno}"

        event_dict["loc"] = file_location
        if logger_name and logger_name != "root":
            event_dict["logger"] = logger_name
        if funcname and funcname not in ("<module>", "<lambda>"):
            event_dict["func"] = funcname

    except (ValueError, AttributeError, IndexError) as e:
        event_dict["loc"] = f"unknown:{e.__class__.__name__}"

    return event_dict


def setup_logging():
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    root_logger.setLevel(config.log_level)

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.ExtraAdder(),
        add_caller_info,
        sanitize_tokens,
    ]

    structlog.configure(
        processors=shared_processors
        + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,  # noqa
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        structlog.stdlib.ProcessorFormatter(
            processor=structlog.processors.JSONRenderer(ensure_ascii=False),
            foreign_pre_chain=shared_processors,
        )
    )
    root_logger.addHandler(console_handler)

    for logger_name in ["uvicorn", "uvicorn.error", "uvicorn.access", "watchfiles"]:
        uvicorn_logger = logging.getLogger(logger_name)
        uvicorn_logger.handlers.clear()
        uvicorn_logger.propagate = True

    uvicorn_access_logger = logging.getLogger("uvicorn.access")
    uvicorn_access_logger.addFilter(RequestIDFilter())
    uvicorn_access_logger.propagate = False
