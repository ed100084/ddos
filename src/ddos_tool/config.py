from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class Rate(BaseModel):
    """Token-bucket pacing: target ops (requests/packets) per second."""

    rps: int = Field(default=10_000, ge=1, description="target ops per second")


class HttpPayload(BaseModel):
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None

    @field_validator("method")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()


class UdpPayload(BaseModel):
    size: int = Field(default=512, ge=8, le=65_507, description="payload bytes per packet")
    fill: str = "x"

    def encoded(self) -> bytes:
        unit = self.fill.encode() or b"x"
        return (unit * ((self.size // len(unit)) + 1))[: self.size]


class Config(BaseModel):
    target: str
    attack: Literal["http", "udp", "syn"]
    duration_sec: float = Field(default=60.0, gt=0)
    rate: Rate = Field(default_factory=Rate)
    workers: int = Field(default=8, ge=1, le=512)
    http: HttpPayload | None = None
    udp: UdpPayload | None = None

    @model_validator(mode="after")
    def _check_target(self) -> Config:
        if self.attack == "http" and not self.target.startswith(("http://", "https://")):
            raise ValueError(f"http target must be a full URL (got {self.target!r})")
        if self.attack == "udp" and ":" not in self.target.rsplit("/", 1)[-1]:
            raise ValueError(f"udp target must be host:port (got {self.target!r})")
        return self


def load_yaml(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"config root must be a mapping (got {type(data).__name__})")
    return data
