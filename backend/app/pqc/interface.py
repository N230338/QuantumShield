"""Placeholder API for future post-quantum cryptography integration.

PQC is classical cryptography that runs on classical computers and needs no quantum
computer. PQC and QKD are different, complementary technologies. Intended future work
includes integrating NIST-standardized algorithms such as ML-KEM; none are implemented
or simulated by this placeholder.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

PQC_STATUS = "Planned – future scope"
_PLACEHOLDER_ERROR = "PQC is not implemented in this prototype (future scope)"


class PQCProvider(ABC):
    """Abstract contract for a future classical post-quantum cryptography provider."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the provider's display name."""
        raise NotImplementedError

    @property
    @abstractmethod
    def status(self) -> str:
        """Return the provider implementation status."""
        raise NotImplementedError

    @abstractmethod
    def keygen(self) -> Any:
        """Generate a future provider's public and secret key pair."""
        raise NotImplementedError

    @abstractmethod
    def encapsulate(self, public_key: Any) -> Any:
        """Encapsulate a future shared secret to a public key."""
        raise NotImplementedError

    @abstractmethod
    def decapsulate(self, secret_key: Any, ciphertext: Any) -> Any:
        """Decapsulate a future shared secret from its ciphertext."""
        raise NotImplementedError


class PlaceholderPQCProvider(PQCProvider):
    """Non-functional placeholder; no PQC algorithm is present in this prototype."""

    @property
    def name(self) -> str:
        """Return a label identifying this non-functional placeholder."""
        return "PQC placeholder"

    @property
    def status(self) -> str:
        """Return the exact user-facing future-scope status."""
        return PQC_STATUS

    def keygen(self) -> Any:
        """Raise because PQC key generation is not implemented."""
        raise NotImplementedError(_PLACEHOLDER_ERROR)

    def encapsulate(self, public_key: Any) -> Any:
        """Raise because PQC encapsulation is not implemented."""
        raise NotImplementedError(_PLACEHOLDER_ERROR)

    def decapsulate(self, secret_key: Any, ciphertext: Any) -> Any:
        """Raise because PQC decapsulation is not implemented."""
        raise NotImplementedError(_PLACEHOLDER_ERROR)


def get_pqc_status() -> dict[str, Any]:
    """Return truthful status information for the placeholder interface."""
    return {
        "implemented": False,
        "status": PQC_STATUS,
        "note": (
            "PQC is classical cryptography and differs from QKD; future scope may integrate "
            "a NIST-standardized algorithm such as ML-KEM."
        ),
    }
