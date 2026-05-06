from contextlib import asynccontextmanager

from fastapi import FastAPI

from network_a import db
from network_a.api.routes import router


@asynccontextmanager
async def lifespan(app: FastAPI):
    await db.init_pool()
    yield
    await db.close_pool()


app = FastAPI(
    title="Network A — Summary Provider",
    version="0.2.0",
    description="Privacy-preserving UE behavioural summary API",
    lifespan=lifespan,
)
app.include_router(router, prefix="/v1")
