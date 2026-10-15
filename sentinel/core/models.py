"""Data models that cross module boundaries."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """One normalised scanner result, whichever tool produced it."""

    tool: str
    rule_id: str
    message: str
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    severity: str = "warning"
    snippet: str = ""
    cwes: list[int] = Field(default_factory=list)
    owasp: list[str] = Field(default_factory=list)
    language: str = "unknown"
