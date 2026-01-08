from fastapi import APIRouter

from tiny.routers.auth import router as auth_router
from tiny.routers.health import router as health_router
from tiny.routers.user import router as user_router

api_router = APIRouter()


api_router.include_router(auth_router, prefix="/api/auth", tags=["auth"])

api_router.include_router(user_router, prefix="/api/users", tags=["users"])

api_router.include_router(health_router, tags=["health"], include_in_schema=False)
