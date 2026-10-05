"""Tests for the standardized ML-KEM-768 provider."""

from __future__ import annotations

import pytest

from backend.app.pqc.interface import MLKEM768Provider, PQCError, get_pqc_status


def test_mlkem768_sender_and_receiver_derive_the_same_secret():
    exchange = MLKEM768Provider().establish_shared_secret()

    assert len(exchange.ciphertext) == 1088
    assert exchange.sender_secret == exchange.receiver_secret


def test_mlkem768_rejects_invalid_inputs():
    provider = MLKEM768Provider()

    with pytest.raises(PQCError, match="public key has an invalid"):
        provider.encapsulate(b"invalid")
    with pytest.raises(PQCError, match="private key has an invalid"):
        provider.decapsulate(b"invalid", b"invalid")


def test_private_keys_and_shared_secrets_are_hidden_from_repr():
    exchange = MLKEM768Provider().establish_shared_secret()
    display = repr(exchange)

    assert exchange.sender_secret.hex() not in display
    assert exchange.receiver_secret.hex() not in display
    assert get_pqc_status()["implemented"] is True
    assert get_pqc_status()["algorithm"] == "ML-KEM-768 (NIST FIPS 203)"
