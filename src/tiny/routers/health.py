import asyncio

from fastapi import APIRouter, HTTPException, status

from tiny.core.database import db
from tiny.core.redis import redis_manager

router = APIRouter()

@router.get("/health")
async def health_check():
    return {"status": "ok"}


@router.get("/ready")
async def ready_check():
    db_task = asyncio.wait_for(db.check_alive_db(), timeout=0.5)
    redis_task = redis_manager.check_alive(timeout=0.5)

    db_ok, redis_ok = await asyncio.gather(db_task, redis_task, return_exceptions=True)

    if isinstance(db_ok, Exception):
        db_ok = False
    if isinstance(redis_ok, Exception):
        redis_ok = False

    if db_ok and redis_ok:
        return {
            "status": "ok",
            "db": "ok",
            "redis": "ok",
        }

    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail={
            "status": "not ready",
            "db": bool(db_ok),
            "redis": bool(redis_ok),
        },
    )