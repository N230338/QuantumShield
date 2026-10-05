from __future__ import annotations

import json
from dataclasses import replace

import pytest

from backend.app.bb84.core import QBERDecision, run_bb84_qiskit
from backend.app.messaging.secure_channel import (
    DecryptionError,
    EncryptedMessage,
    KeyNotAcceptedError,
    KeyTooShortError,
    bits_to_bytes,
    check_key_usable,
    derive_aes_key,
    decrypt_message,
    encrypt_message,
    key_fingerprint,
    receive_secure_message,
    send_secure_message,
)
from backend.app.pqc.interface import MLKEM768Provider

MESSAGE = "Government meeting at 10 AM"


@pytest.fixture(scope="module")
def accepted_result():
    """Reuse one accepted Aer run across message-layer tests."""
    return run_bb84_qiskit(256, seed=7)


@pytest.fixture(scope="module")
def rejected_result():
    """Reuse one rejected Aer run across message-layer tests."""
    return run_bb84_qiskit(256, seed=7, attack=True)


@pytest.fixture(scope="module")
def tiny_result():
    """Reuse one deliberately insufficient-data Aer run."""
    return run_bb84_qiskit(8, seed=5)


def test_normal_run_sends_and_receives_actual_message(accepted_result):
    encrypted = send_secure_message(accepted_result, MESSAGE)

    assert receive_secure_message(accepted_result, encrypted) == MESSAGE


@pytest.mark.parametrize("mode", ["ml-kem", "hybrid"])
def test_mlkem_and_hybrid_modes_encrypt_and_authenticate_message(accepted_result, mode):
    exchange = MLKEM768Provider().establish_shared_secret()
    encrypted = send_secure_message(
        accepted_result,
        MESSAGE,
        mode=mode,
        mlkem_secret=exchange.sender_secret,
    )

    assert encrypted.mode == mode
    assert receive_secure_message(
        accepted_result,
        encrypted,
        mlkem_secret=exchange.receiver_secret,
    ) == MESSAGE


@pytest.mark.parametrize("mode", ["ml-kem", "hybrid"])
def test_mlkem_and_hybrid_modes_reject_tampered_ciphertext(accepted_result, mode):
    exchange = MLKEM768Provider().establish_shared_secret()
    encrypted = send_secure_message(
        accepted_result,
        MESSAGE,
        mode=mode,
        mlkem_secret=exchange.sender_secret,
    )
    changed = bytearray(encrypted.ciphertext)
    changed[0] ^= 1

    with pytest.raises(DecryptionError, match="authentication or decryption failed"):
        receive_secure_message(
            accepted_result,
            replace(encrypted, ciphertext=bytes(changed)),
            mlkem_secret=exchange.receiver_secret,
        )


def test_mode_and_route_are_domain_separated_in_key_derivation():
    salt = b"s" * 16
    bb84_bits = [1, 0, 1, 1] * 16
    kem_secret = b"k" * 32

    bb84_key = derive_aes_key("bb84", salt, bb84_key_bits=bb84_bits)
    mlkem_key = derive_aes_key("ml-kem", salt, mlkem_secret=kem_secret)
    hybrid_key = derive_aes_key(
        "hybrid",
        salt,
        aad=b"sender -> receiver",
        bb84_key_bits=bb84_bits,
        mlkem_secret=kem_secret,
    )
    other_route_key = derive_aes_key(
        "hybrid",
        salt,
        aad=b"sender -> other",
        bb84_key_bits=bb84_bits,
        mlkem_secret=kem_secret,
    )

    assert len({bb84_key, mlkem_key, hybrid_key, other_route_key}) == 4


def test_alice_and_bob_key_fingerprints_match(accepted_result):
    assert key_fingerprint(accepted_result["alice_final_key"]) == key_fingerprint(
        accepted_result["bob_final_key"]
    )


def test_rejected_attack_key_cannot_send(rejected_result):
    assert rejected_result["decision"] == QBERDecision.REJECTED
    with pytest.raises(KeyNotAcceptedError, match="ACCEPTED key is required"):
        send_secure_message(rejected_result, MESSAGE)


def test_tiny_insufficient_key_cannot_send(tiny_result):
    with pytest.raises((KeyNotAcceptedError, KeyTooShortError)):
        send_secure_message(tiny_result, MESSAGE)


def test_tampered_ciphertext_fails_authentication(accepted_result):
    encrypted = send_secure_message(accepted_result, MESSAGE)
    ciphertext = bytearray(encrypted.ciphertext)
    ciphertext[0] ^= 1

    with pytest.raises(DecryptionError, match="authentication or decryption failed"):
        receive_secure_message(accepted_result, replace(encrypted, ciphertext=bytes(ciphertext)))


def test_wrong_receiver_key_fails_authentication(accepted_result):
    encrypted = send_secure_message(accepted_result, MESSAGE)
    wrong_result = dict(accepted_result.__dict__)
    wrong_result["key_status"] = "ACCEPTED"
    wrong_key = list(accepted_result["bob_final_key"])
    wrong_key[0] ^= 1
    wrong_result["bob_final_key"] = wrong_key

    with pytest.raises(DecryptionError, match="authentication or decryption failed"):
        decrypt_message(encrypted, wrong_key)


def test_encryptions_use_fresh_nonce_and_salt(accepted_result):
    key_bits = accepted_result["alice_final_key"]
    first = encrypt_message(MESSAGE, key_bits)
    second = encrypt_message(MESSAGE, key_bits)

    assert first.nonce != second.nonce
    assert first.salt != second.salt
    assert first.ciphertext != second.ciphertext


def test_encrypted_message_serializes_and_round_trips(accepted_result):
    encrypted = send_secure_message(accepted_result, MESSAGE)
    serialized = encrypted.to_dict()

    json.dumps(serialized)
    restored = EncryptedMessage.from_dict(serialized)
    assert restored == encrypted
    assert receive_secure_message(accepted_result, restored) == MESSAGE


def test_unicode_message_round_trips(accepted_result):
    message = "सरकारी बैठक सुबह दस बजे 🔐"
    encrypted = send_secure_message(accepted_result, message)

    assert receive_secure_message(accepted_result, encrypted) == message


@pytest.mark.parametrize("message", ["x", "a" * 100, "b" * 1000, "c" * 10000])
def test_long_message_round_trips_without_truncation(accepted_result, message):
    encrypted = send_secure_message(accepted_result, message)

    assert receive_secure_message(accepted_result, encrypted) == message


def test_multiline_message_preserves_whitespace_and_line_breaks(accepted_result):
    message = "  First line\nSecond line\r\n  Third line  "
    encrypted = send_secure_message(accepted_result, message)

    assert receive_secure_message(accepted_result, encrypted) == message


def test_ciphertext_does_not_contain_plaintext(accepted_result):
    plaintext = MESSAGE.encode("utf-8")
    encrypted = send_secure_message(accepted_result, MESSAGE)

    assert plaintext not in encrypted.ciphertext


def test_bits_to_bytes_known_values_and_padding():
    assert bits_to_bytes([]) == b""
    assert bits_to_bytes([1]) == b"\x80"
    assert bits_to_bytes([1, 0, 1, 0, 1, 0, 1, 0]) == b"\xaa"
    assert bits_to_bytes([1, 0, 0, 0, 0, 0, 0, 0, 1]) == b"\x80\x80"


def test_public_qber_sample_positions_are_not_key_material(accepted_result):
    sample = set(accepted_result["sampled_positions"])
    expected_positions = [
        index for index in accepted_result["matching_positions"] if index not in sample
    ]
    expected_alice = [accepted_result["alice_bits"][index] for index in expected_positions]
    expected_bob = [accepted_result["bob_bits"][index] for index in expected_positions]

    assert accepted_result["alice_final_key"] == expected_alice
    assert accepted_result["bob_final_key"] == expected_bob
    assert len(accepted_result["final_key"]) == len(expected_positions)


def test_check_key_usable_rejects_short_accepted_key(accepted_result):
    short_result = dict(accepted_result.__dict__)
    short_result["alice_final_key"] = [0] * 63

    with pytest.raises(KeyTooShortError, match=r"256\+ qubits"):
        check_key_usable(short_result)


def test_hybrid_send_rejects_short_accepted_bb84_key(accepted_result):
    short_result = dict(accepted_result.__dict__)
    short_result["alice_final_key"] = [0] * 63

    with pytest.raises(KeyTooShortError):
        send_secure_message(
            short_result,
            MESSAGE,
            mode="hybrid",
            mlkem_secret=b"k" * 32,
        )
