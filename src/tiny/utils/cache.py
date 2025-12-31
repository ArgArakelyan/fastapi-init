"""Custom key builders for fastapi_cache2"""


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
