from prometheus_client import PLATFORM_COLLECTOR  # noqa
from prometheus_client import Counter  # noqa
from prometheus_client import Gauge  # noqa
from prometheus_client import Histogram  # noqa
from prometheus_client import (GC_COLLECTOR, PROCESS_COLLECTOR,
                               CollectorRegistry)

registry = CollectorRegistry()

registry.register(PROCESS_COLLECTOR)
registry.register(GC_COLLECTOR)
registry.register(PLATFORM_COLLECTOR)
