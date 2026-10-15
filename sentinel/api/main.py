from fastapi import FastAPI

from sentinel import __version__
from sentinel.api.routes.benchmark import router as benchmark_router

app = FastAPI(title="OWASP Sentinel", version=__version__)

app.include_router(benchmark_router)

app.include_router(benchmark_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
