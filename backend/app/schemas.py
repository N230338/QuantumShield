"""Pydantic request models for the FastAPI dashboard."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class BB84RunRequest(BaseModel):
    """Options for one simulated BB84 key-establishment run."""

    n_qubits: int = Field(default=256, ge=8, le=512)
    attack: bool = False
    intercept_fraction: float = Field(default=1.0, ge=0.0, le=1.0)
    qber_sample_fraction: float = Field(default=0.25, gt=0.0, le=1.0)
    qber_threshold: float = Field(default=0.11, ge=0.0, le=1.0)
    noise_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    seed: int | None = None


class MessageSendRequest(BaseModel):
    """Actual plaintext message and its established BB84 session identifier."""

    session_id: str
    message: str = Field(min_length=1)

    @field_validator("message")
    @classmethod
    def require_non_whitespace_message(cls, value: str) -> str:
        """Reject empty content without changing whitespace in a valid message."""
        if not value.strip():
            raise ValueError("Message must contain non-whitespace text.")
        return value


class MessageReceiveRequest(BaseModel):
    """Request to decrypt the stored message for a BB84 session."""

    session_id: str


class MessagePipelineRequest(BaseModel):
    """One actual message, route, security mode, and fresh BB84 simulation options."""

    sender: str
    receiver: str
    message: str
    security_mode: Literal["bb84", "ml-kem", "hybrid"] = "hybrid"
    n_qubits: int = Field(default=256, ge=8, le=512)
    attack: bool = False
    intercept_fraction: float = Field(default=1.0, ge=0.0, le=1.0)
    qber_sample_fraction: float = Field(default=0.25, gt=0.0, le=1.0)
    qber_threshold: float = Field(default=0.11, ge=0.0, le=1.0)
    noise_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    seed: int | None = None

    @field_validator("message")
    @classmethod
    def require_non_whitespace_message(cls, value: str) -> str:
        """Reject empty content without changing whitespace in a valid message."""
        if not value.strip():
            raise ValueError("Message must contain non-whitespace text.")
        return value


class ComparisonRequest(BaseModel):
    """Options for a background normal-versus-attack experiment."""

    runs: int = Field(default=10, ge=1, le=100)
    n_qubits: int = Field(default=256, ge=8, le=512)
    base_seed: int | None = None
    qber_sample_fraction: float = Field(default=0.25, gt=0.0, le=1.0)
    qber_threshold: float = Field(default=0.11, ge=0.0, le=1.0)
    intercept_fraction: float = Field(default=1.0, ge=0.0, le=1.0)
