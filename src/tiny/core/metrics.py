from prometheus_client import PLATFORM_COLLECTOR  # noqa
from prometheus_client import Counter  # noqa
from prometheus_client import Gauge  # noqa
from prometheus_client import Histogram  # noqa
from prometheus_client import GC_COLLECTOR, PROCESS_COLLECTOR, CollectorRegistry
from prometheus_fastapi_instrumentator import Instrumentator

registry = CollectorRegistry()

registry.register(PROCESS_COLLECTOR)
registry.register(GC_COLLECTOR)
registry.register(PLATFORM_COLLECTOR)


def setup_metrics(app):
    Instrumentator(
        excluded_handlers=[
            "/metrics.py",
            "/openapi.json",
            "/docs",
            "/health",
            "/ready",
        ],
        should_group_status_codes=False,
        registry=registry,
    ).instrument(app)
