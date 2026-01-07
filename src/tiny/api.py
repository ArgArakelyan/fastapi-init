from fastapi import APIRouter

from tiny.routers.auth import router as auth_router

api_router = APIRouter()


api_router.include_router(auth_router, prefix="/api/auth", tags=["auth"])
