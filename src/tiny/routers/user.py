from fastapi import APIRouter, Depends, Request, Query

from tiny.core.dependencies import verify_bearer_token
from tiny.core.rate_limiting import rate_limit
from tiny.models.user import UserRead
from tiny.repositories.user import UserRepository, get_user_repository
from tiny.services.auth import CurrentUser

router = APIRouter()


@router.get("/me", response_model=UserRead)
@rate_limit("10/minute")
async def me(
    request: Request,  # noqa
    current_user: CurrentUser,
    user_repository: UserRepository = Depends(get_user_repository),
):
    return await user_repository.get_by_id(current_user.id)


# bearer auth only (for admins)
@router.get(
    "", dependencies=[Depends(verify_bearer_token)], response_model=list[UserRead]
)
@rate_limit("10/minute")
async def get_users(
    request: Request, # noqa
    limit: int = 0,
    offset: int = 0,
    user_repository: UserRepository = Depends(get_user_repository),
):
    return await user_repository.get_all(limit=limit, offset=offset)


@router.get(
    "/find-by",
    dependencies=[Depends(verify_bearer_token)],
    response_model=UserRead,
)
@rate_limit("100/minute")
async def get_user_by_email(
    request: Request, # noqa
    email: str = Query(..., description="User email"),
    user_repository: UserRepository = Depends(get_user_repository),
):
    return await user_repository.get_by_email(email)


@router.get(
    "/{user_id}", dependencies=[Depends(verify_bearer_token)], response_model=UserRead
)
@rate_limit("100/minute")
async def get_user_by_id(
    request: Request, # noqa
    user_id: int,
    user_repository: UserRepository = Depends(get_user_repository),
):
    return await user_repository.get_by_id(user_id)

