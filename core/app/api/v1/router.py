from fastapi import APIRouter

from app.api.v1.endpoints import auth, assets, events, github_scan, ingest, stealer

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(assets.router)
api_router.include_router(events.router)
api_router.include_router(ingest.router)
api_router.include_router(stealer.router)
api_router.include_router(github_scan.router)

