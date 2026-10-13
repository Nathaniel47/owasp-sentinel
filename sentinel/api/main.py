from fastapi import FastAPI

from sentinel import __version__

app = FastAPI(title="OWASP Sentinel", version=__version__)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
