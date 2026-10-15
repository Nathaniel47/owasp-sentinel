"""Public demo: paste or pick an example, get findings (and optional AI triage)."""

from __future__ import annotations

from urllib.parse import parse_qs

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse

from sentinel.api import demo
from sentinel.api.routes.benchmark import ROOT, env

router = APIRouter()
demo.load_examples(ROOT / "web" / "examples")
demo.load_precomputed(ROOT / "demo-cache" / "examples.json")


def _client_key(request: Request) -> str:
    """The address the platform proxy saw: the last X-Forwarded-For hop."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def _page(
    request: Request,
    *,
    code: str = "",
    language: str = "java",
    use_llm: bool = False,
    result: demo.ScanView | None = None,
    error: str = "",
    status: int = 200,
    example: str = "",
) -> HTMLResponse:
    html = env.get_template("index.html").render(
        code=code,
        language=language,
        use_llm=use_llm,
        result=result,
        error=error,
        example=example,
        examples=demo.examples(),
        labels=demo.LANGUAGE_LABELS,
        llm_enabled=demo.llm_enabled(),
        limit=demo.max_bytes(),
    )
    return HTMLResponse(html, status_code=status)


async def _read_form(request: Request) -> dict[str, str]:
    cap = demo.max_bytes() * 3 + 2000  # percent-encoding can triple the size
    body = b""
    async for chunk in request.stream():
        body += chunk
        if len(body) > cap:
            raise demo.DemoError(413, f"Snippet too large (limit {cap // 3} bytes).")
    parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return {k: v[0] for k, v in parsed.items()}


async def _run(
    request: Request, code: str, language: str, use_llm: bool, example: str = ""
) -> HTMLResponse:
    key = _client_key(request)
    try:
        if not demo.scan_limiter.allow(key):
            raise demo.DemoError(429, "Too many scans. Wait a minute and retry.")
        result = await run_in_threadpool(
            demo.scan_snippet,
            code,
            language,
            ROOT,
            use_llm=use_llm,
            llm_key=key,
        )
    except demo.DemoError as exc:
        return _page(
            request,
            code=code,
            language=language,
            use_llm=use_llm,
            error=exc.message,
            status=exc.status,
        )
    return _page(
        request,
        code=code,
        language=language,
        use_llm=use_llm,
        result=result,
        example=example,
    )


@router.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    return _page(request)


@router.get("/try/{example_id}", response_class=HTMLResponse)
async def try_example(request: Request, example_id: str) -> HTMLResponse:
    ex = demo.examples().get(example_id)
    if ex is None:
        return _page(request, error="Unknown example.", status=404)
    return await _run(request, ex["code"], ex["language"], False, example_id)


@router.post("/scan", response_class=HTMLResponse)
async def scan_form(request: Request) -> HTMLResponse:
    try:
        form = await _read_form(request)
    except demo.DemoError as exc:
        return _page(request, error=exc.message, status=exc.status)
    return await _run(
        request,
        form.get("code", ""),
        form.get("language", ""),
        form.get("use_llm") == "1",
    )
