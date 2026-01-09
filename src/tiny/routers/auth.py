from fastapi import (APIRouter, Depends, HTTPException, Request, Response,
                     status)

from tiny.core.rate_limiting import auth_rate_limit
from tiny.models.auth import AuthBase
from tiny.services.auth import (AuthService, get_auth_service,
                                get_optional_current_user)

router = APIRouter()


@router.post("/register")
@auth_rate_limit("auth_register")
async def auth_register(
    request: Request,  # noqa
    user_in: AuthBase,
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
    user_in: AuthBase,
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

    response.set_cookie(
        key="refresh_token",
        value=result["refresh_token"],
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60,  # 7 дней в секундах
        path="/",
    )

    return {
        "result": "success",
        "access_token": result["access_token"],
        "user_id": result["user_id"],
        "email": result["email"],
    }


@router.post("/logout")
async def auth_logout(response: Response):
    response.delete_cookie(key="access_token")
    return {"result": "success", "msg": "You have been logged out"}


@router.post("/refresh")
@auth_rate_limit("auth_refresh")
async def auth_refresh(
    request: Request,
    response: Response,
    auth_service: AuthService = Depends(get_auth_service),
):
    # Берем refresh_token из cookies
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "result": "failed",
                "error": "refresh_token_missing",
                "msg": "Refresh token not found in cookies",
            },
        )

    # Обновляем токены
    new_tokens = await auth_service.refresh_token(refresh_token)

    # Обновляем cookies
    response.set_cookie(
        key="access_token",
        value=new_tokens["access_token"],
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=1800,
        path="/",
    )

    response.set_cookie(
        key="refresh_token",
        value=new_tokens["refresh_token"],  # Новый refresh токен (ротация)
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=7 * 24 * 60 * 60,
        path="/",
    )

    return {
        "result": "success",
        "access_token": new_tokens["access_token"],
    }
