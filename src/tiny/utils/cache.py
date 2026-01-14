import json
from typing import Any, Optional


def serialize(value: Any) -> str:
    return json.dumps(value)


def deserialize(value: Optional[bytes]) -> Optional[dict | bool | None]:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None
