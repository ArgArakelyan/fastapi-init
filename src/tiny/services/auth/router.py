from fastapi import (APIRouter, Depends, HTTPException, Request, Response,
                     status)
from fastapi_cache.decorator import cache
from tiny.core.rate_limiting import auth_rate_limit
from tiny.services.auth.models import AuthLogin, AuthRegister
from tiny.services.auth.service import (AuthService, CurrentUser,
                                        get_auth_service,
                                        get_optional_current_user)

router = APIRouter()


@router.post("/register")
@auth_rate_limit("auth_login")
async def auth_register(
    request: Request,  # noqa
    user_in: AuthRegister,
    current_user: int = Depends(get_optional_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    if current_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "result": "failed",
                "error": "already_logged_in",
                "msg": "You already logged in",
            },
        )

    return await auth_service.register(user_in)


@router.post("/login")
@auth_rate_limit("auth_login")
async def auth_login(
    request: Request,
    response: Response,
    user_in: AuthLogin,
    current_user: int = Depends(get_optional_current_user),
    auth_service: AuthService = Depends(get_auth_service),
):
    if current_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "result": "failed",
                "error": "already_authenticated",
                "msg": "You already logged in",
            },
        )

    result = await auth_service.login(
        email=user_in.email,
        password=user_in.password,
        client_ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
    )

    response.set_cookie(
        key="access_token",
        value=result["access_token"],
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=1800,
        path="/",
    )

    return {"result": "success", "access_token": result["access_token"]}


@router.post("/logout")
async def auth_logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"result": "success", "msg": "You have been logged out"}


@router.get("/me")
@auth_rate_limit("account_refresh")
async def account_info(request: Request, current_user: CurrentUser):  # noqa
    return {"result": "success", "user_id": current_user.id}
