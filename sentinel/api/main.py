from collections.abc import Awaitable, Callable

from fastapi import FastAPI, Request, Response

from sentinel import __version__
from sentinel.api.routes.benchmark import router as benchmark_router
from sentinel.api.routes.demo import router as demo_router

app = FastAPI(title="OWASP Sentinel", version=__version__)

# The pages use no JavaScript and no third-party assets, so the policy can be tight.
# frame-ancestors is left open on purpose: Hugging Face shows Spaces in an iframe.
CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; "
    "form-action 'self'; base-uri 'none'"
)


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


app.include_router(demo_router)
app.include_router(benchmark_router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
