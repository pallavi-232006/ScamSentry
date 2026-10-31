from fastapi import APIRouter
from app.api.v1.scan import router as scan_router
from app.api.v1.history import router as history_router
from app.api.v1.stats import router as stats_router

api_router = APIRouter()
api_router.include_router(scan_router)
api_router.include_router(history_router)
api_router.include_router(stats_router)

