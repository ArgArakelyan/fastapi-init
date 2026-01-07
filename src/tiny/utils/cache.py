"""Custom key builders for fastapi_cache2"""

import json
from typing import Any, Optional


def user_key_builder(
    func,
    namespace: str = "",
    request=None,
    response=None,
    *args,
    **kwargs,
):
    user_id = kwargs.get("user_id")

    if user_id is None and args:
        user_id = args[0]

    if user_id is None and request is not None:
        user_id = request.path_params.get("user_id")

    return f"{namespace}:{user_id}"


def serialize(value: Any) -> str:
    return json.dumps(value)


def deserialize(value: Optional[bytes]) -> Optional[dict | bool | None]:
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None
