from fastapi import FastAPI

from network_b.api.routes import router

app = FastAPI(
    title="Network B — Access Decision Engine",
    version="0.1.0",
    description="Hybrid policy engine for UE access tiering",
)
app.include_router(router, prefix="/v1")
