from __future__ import annotations

import pytest

from backend.app.pqc.interface import (
    PQC_STATUS,
    PlaceholderPQCProvider,
    get_pqc_status,
)


def test_pqc_status_is_truthfully_not_implemented():
    status = get_pqc_status()

    assert status["implemented"] is False
    assert status["status"] == "Planned – future scope" == PQC_STATUS


def test_placeholder_provider_methods_raise_not_implemented():
    provider = PlaceholderPQCProvider()

    with pytest.raises(NotImplementedError, match="PQC is not implemented"):
        provider.keygen()
    with pytest.raises(NotImplementedError, match="PQC is not implemented"):
        provider.encapsulate(b"public-key-placeholder")
    with pytest.raises(NotImplementedError, match="PQC is not implemented"):
        provider.decapsulate(b"secret-key-placeholder", b"ciphertext-placeholder")
