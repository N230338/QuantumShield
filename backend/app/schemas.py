"""Pydantic request models for the FastAPI dashboard."""

from __future__ import annotations

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
    message: str = Field(min_length=1, max_length=10000)


class MessageReceiveRequest(BaseModel):
    """Request to decrypt the stored message for a BB84 session."""

    session_id: str


class MessagePipelineRequest(BaseModel):
    """One actual message, its department route, and a fresh BB84 round's options."""

    sender: str
    receiver: str
    message: str
    n_qubits: int = Field(default=256, ge=8, le=512)
    attack: bool = False
    intercept_fraction: float = Field(default=1.0, ge=0.0, le=1.0)
    noise_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    seed: int | None = None

    @field_validator("message")
    @classmethod
    def trim_and_validate_message(cls, value: str) -> str:
        """Trim surrounding whitespace and require 1 through 500 characters."""
        trimmed = value.strip()
        if not 1 <= len(trimmed) <= 500:
            raise ValueError("Message must contain 1 to 500 characters after trimming.")
        return trimmed


class ComparisonRequest(BaseModel):
    """Options for a background normal-versus-attack experiment."""

    runs: int = Field(default=10, ge=1, le=100)
    n_qubits: int = Field(default=256, ge=8, le=512)
    base_seed: int | None = None
    qber_sample_fraction: float = Field(default=0.25, gt=0.0, le=1.0)
    qber_threshold: float = Field(default=0.11, ge=0.0, le=1.0)
    intercept_fraction: float = Field(default=1.0, ge=0.0, le=1.0)


class DetectionVsQubitsRequest(BaseModel):
    """Options for a background detection-rate versus qubit-count experiment."""

    qubit_counts: list[int] = Field(default_factory=lambda: [32, 64, 128, 256])
    runs: int = Field(default=10, ge=1, le=100)
    base_seed: int | None = None
    qber_sample_fraction: float = Field(default=0.25, gt=0.0, le=1.0)
    qber_threshold: float = Field(default=0.11, ge=0.0, le=1.0)
    intercept_fraction: float = Field(default=1.0, ge=0.0, le=1.0)
