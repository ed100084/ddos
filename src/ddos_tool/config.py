from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class Rate(BaseModel):
    """Token-bucket pacing: target ops (requests/packets) per second."""

    rps: int = Field(default=10_000, ge=1, description="target ops per second")


class Ramp(BaseModel):
    """Stepwise ramp-up: linearly move from start_rps to end_rps over the run.

    `steps` is the number of discrete levels; each level holds for duration/steps.
    """

    start_rps: int = Field(default=1_000, ge=1)
    end_rps: int = Field(default=5_000, ge=1)
    steps: int = Field(default=5, ge=1, le=64)

    def rates(self) -> list[int]:
        if self.steps == 1 or self.start_rps == self.end_rps:
            return [self.end_rps]
        span = (self.end_rps - self.start_rps) / (self.steps - 1)
        return [max(1, round(self.start_rps + i * span)) for i in range(self.steps)]


class HttpPayload(BaseModel):
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    body_template: str | None = None
    headers_random: dict[str, list[str]] = Field(default_factory=dict)

    @field_validator("method")
    @classmethod
    def _upper(cls, v: str) -> str:
        return v.upper()


class UdpPayload(BaseModel):
    size: int = Field(default=512, ge=8, le=65_507, description="payload bytes per packet")
    fill: str = "x"

    def encoded(self) -> bytes:
        if self.fill == "random":
            return os.urandom(self.size)
        unit = self.fill.encode() or b"x"
        return (unit * ((self.size // len(unit)) + 1))[: self.size]


class TcpPayload(BaseModel):
    # Optional extra ports to round-robin across; defaults to the target's port.
    ports: list[int] = Field(default_factory=list)

    @field_validator("ports")
    @classmethod
    def _valid_ports(cls, v: list[int]) -> list[int]:
        if any(not (1 <= p <= 65_535) for p in v):
            raise ValueError(f"tcp ports out of range: {v}")
        return v


class SynPayload(BaseModel):
    """SYN options; source spoofing is opt-in and requires raw-socket privileges."""

    spoof_src: str | None = None

    @field_validator("spoof_src")
    @classmethod
    def _valid_spoof_src(cls, v: str | None) -> str | None:
        if v is None:
            return None
        if v == "random":
            return v
        try:
            network = ipaddress.ip_network(v, strict=False)
        except ValueError as exc:
            raise ValueError("spoof_src must be 'random' or an IPv4 CIDR") from exc
        if network.version != 4:
            raise ValueError("spoof_src must be 'random' or an IPv4 CIDR")
        return v


class ReplayPayload(BaseModel):
    file: str
    rate_factor: float = Field(default=1.0, gt=0)
    max_packets: int = Field(default=100_000, ge=1)
    max_rps: int = Field(default=10_000, ge=1)


class Config(BaseModel):
    target: str
    attack: Literal["http", "udp", "syn", "tcp", "tls", "replay"]
    duration_sec: float = Field(default=60.0, gt=0)
    rate: Rate = Field(default_factory=Rate)
    workers: int = Field(default=8, ge=1, le=512)
    ramp: Ramp | None = None
    http: HttpPayload | None = None
    udp: UdpPayload | None = None
    tcp: TcpPayload | None = None
    syn: SynPayload | None = None
    replay: ReplayPayload | None = None

    @model_validator(mode="after")
    def _check_target(self) -> Config:
        if self.attack == "http" and not self.target.startswith(("http://", "https://")):
            raise ValueError(f"http target must be a full URL (got {self.target!r})")
        if self.attack in ("udp", "tcp", "syn", "tls", "replay") and ":" not in self.target.rsplit("/", 1)[-1]:
            raise ValueError(f"{self.attack} target must be host:port (got {self.target!r})")
        if self.attack in ("udp", "tcp", "syn", "tls", "replay") and self.target.count(":") > 1:
            raise ValueError("IPv6 targets are not supported; use an IPv4 host:port")
        if self.attack == "replay" and self.replay is None:
            raise ValueError("replay attack requires replay.file")
        return self

    def effective_rps(self) -> int:
        """Starting rate: ramp.start if ramping, else flat rate."""
        return self.ramp.start_rps if self.ramp else self.rate.rps


def load_yaml(path: str | Path) -> dict[str, Any]:
    data = yaml.safe_load(Path(path).read_text()) or {}
    if not isinstance(data, dict):
        raise ValueError(f"config root must be a mapping (got {type(data).__name__})")
    return data
