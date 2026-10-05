"""Protect actual messages using key material established by the BB84 simulation.

BB84 random bits are not the message. BB84 only establishes the key; AES-GCM protects
the actual message. This demonstration uses standard cryptography and does not model a
production QKD system, which would also need error correction, privacy amplification,
and an authenticated classical channel.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DEFAULT_AAD = b"Sender Dept -> Receiver Dept"
DEFAULT_CONTEXT = b"QuantumShield-v1"
AES_GCM_NONCE_BYTES = 12
HKDF_SALT_BYTES = 16
MIN_KEY_BITS = 64
SECURITY_MODES = ("bb84", "ml-kem", "hybrid")
MLKEM_SHARED_SECRET_BYTES = 32


class KeyNotAcceptedError(ValueError):
    """Raised when BB84 did not accept the established key."""


class KeyTooShortError(ValueError):
    """Raised when the post-sampling key is shorter than the configured minimum."""


class DecryptionError(ValueError):
    """Raised when authenticated decryption or UTF-8 decoding fails."""


def bits_to_bytes(bits: list[int]) -> bytes:
    """Pack bits most-significant-bit first, padding the final byte on the right with 0s."""
    packed = bytearray()
    for offset in range(0, len(bits), 8):
        group = bits[offset : offset + 8]
        if any(bit not in (0, 1) for bit in group):
            raise ValueError("Key bits must contain only 0 or 1.")
        value = 0
        for bit in group:
            value = (value << 1) | bit
        value <<= 8 - len(group)
        packed.append(value)
    return bytes(packed)


def derive_session_key(
    key_bits: list[int],
    salt: bytes,
    context: bytes = DEFAULT_CONTEXT,
) -> bytes:
    """Derive a 256-bit AES key from BB84 key bits using HKDF-SHA256."""
    if not key_bits:
        raise KeyTooShortError("The established BB84 key is empty.")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=context,
    ).derive(bits_to_bytes(key_bits))


def derive_aes_key(
    mode: str,
    salt: bytes,
    *,
    aad: bytes = DEFAULT_AAD,
    bb84_key_bits: list[int] | None = None,
    mlkem_secret: bytes | None = None,
) -> bytes:
    """Derive a mode-separated AES-256 key using HKDF-SHA256.

    Hybrid input is encoded as ``label || len(BB84) || BB84 || len(ML-KEM) ||
    ML-KEM`` with 32-bit big-endian lengths, preventing ambiguous concatenation.
    The HKDF info also binds the mode, protocol version, and authenticated route.
    """
    if mode not in SECURITY_MODES:
        raise ValueError("Unsupported security mode.")

    if mode == "bb84":
        if not bb84_key_bits:
            raise KeyTooShortError("The accepted BB84 key is empty.")
        input_key_material = bits_to_bytes(bb84_key_bits)
    elif mode == "ml-kem":
        if not isinstance(mlkem_secret, bytes) or len(mlkem_secret) != MLKEM_SHARED_SECRET_BYTES:
            raise ValueError("ML-KEM shared secret has an invalid type or length.")
        input_key_material = mlkem_secret
    else:
        if not bb84_key_bits:
            raise KeyTooShortError("The accepted BB84 key is empty.")
        if not isinstance(mlkem_secret, bytes) or len(mlkem_secret) != MLKEM_SHARED_SECRET_BYTES:
            raise ValueError("ML-KEM shared secret has an invalid type or length.")
        bb84_material = bits_to_bytes(bb84_key_bits)
        input_key_material = (
            b"QuantumShield hybrid IKM v1\x00"
            + len(bb84_material).to_bytes(4, "big")
            + bb84_material
            + len(mlkem_secret).to_bytes(4, "big")
            + mlkem_secret
        )

    info = b"QuantumShield AES-256-GCM key v1\x00" + mode.encode("ascii") + b"\x00" + aad
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    ).derive(input_key_material)


def key_fingerprint(key_bits: list[int]) -> str:
    """Return a short digest for key comparison, not for key confirmation.

    A real system would use a proper key-confirmation step over an authenticated channel.
    """
    return hashlib.sha256(bits_to_bytes(key_bits)).hexdigest()[:12]


def _get_field(result: Any, name: str, default: Any = None) -> Any:
    """Read a result field from either a mapping or a dict-like BB84 result."""
    if isinstance(result, Mapping):
        return result.get(name, default)
    try:
        return result[name]
    except (KeyError, TypeError, AttributeError):
        return getattr(result, name, default)


def _alice_key(bb84_result: Any) -> list[int]:
    """Return Alice's final key, with compatibility for results carrying only final_key."""
    key = _get_field(bb84_result, "alice_final_key")
    if key is None:
        key = _get_field(bb84_result, "final_key", [])
    return list(key)


def _bob_key(bb84_result: Any) -> list[int]:
    """Return Bob's final key, with compatibility for results carrying only final_key."""
    key = _get_field(bb84_result, "bob_final_key")
    if key is None:
        key = _get_field(bb84_result, "final_key", [])
    return list(key)


def check_key_usable(bb84_result: Any, min_key_bits: int = MIN_KEY_BITS) -> None:
    """Reject unaccepted keys and keys too short for this message-layer demonstration."""
    key_status = _get_field(bb84_result, "key_status")
    if key_status is None:
        decision = _get_field(bb84_result, "decision")
        key_status = getattr(decision, "value", decision)
    if key_status != "ACCEPTED":
        raise KeyNotAcceptedError(
            f"BB84 key status is {key_status or 'UNKNOWN'}; an ACCEPTED key is required."
        )
    if min_key_bits < 0:
        raise ValueError("min_key_bits must not be negative.")
    key_length = len(_alice_key(bb84_result))
    if key_length < min_key_bits:
        raise KeyTooShortError(
            f"The final BB84 key has {key_length} bits; at least {min_key_bits} are required. "
            "Increase the qubit count (256+ qubits are recommended)."
        )


@dataclass(frozen=True)
class EncryptedMessage:
    """AES-GCM message envelope containing ciphertext and its public parameters."""

    ciphertext: bytes
    nonce: bytes
    salt: bytes
    aad: bytes = DEFAULT_AAD
    mode: str = "bb84"

    def to_dict(self) -> dict[str, str]:
        """Return a JSON-compatible base64 representation of the envelope."""
        return {
            "ciphertext": base64.b64encode(self.ciphertext).decode("ascii"),
            "nonce": base64.b64encode(self.nonce).decode("ascii"),
            "salt": base64.b64encode(self.salt).decode("ascii"),
            "aad": base64.b64encode(self.aad).decode("ascii"),
            "security_mode": self.mode,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, str]) -> EncryptedMessage:
        """Parse a JSON-compatible base64 envelope."""
        try:
            return cls(
                ciphertext=base64.b64decode(value["ciphertext"], validate=True),
                nonce=base64.b64decode(value["nonce"], validate=True),
                salt=base64.b64decode(value["salt"], validate=True),
                aad=base64.b64decode(value["aad"], validate=True),
                mode=value.get("security_mode", "bb84"),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Encrypted message must contain valid base64 ciphertext, nonce, salt, and aad.") from exc


def encrypt_message(
    message: str,
    sender_key_bits: list[int],
    *,
    aad: bytes = DEFAULT_AAD,
) -> EncryptedMessage:
    """Encrypt an actual UTF-8 message with AES-256-GCM and fresh random parameters."""
    return encrypt_message_with_secrets(
        message,
        "bb84",
        bb84_key_bits=sender_key_bits,
        aad=aad,
    )


def encrypt_message_with_secrets(
    message: str,
    mode: str,
    *,
    bb84_key_bits: list[int] | None = None,
    mlkem_secret: bytes | None = None,
    aad: bytes = DEFAULT_AAD,
) -> EncryptedMessage:
    """Encrypt with fresh salt/nonce after deriving a mode-specific AES key."""
    if not isinstance(message, str):
        raise TypeError("message must be a string.")
    salt = secrets.token_bytes(HKDF_SALT_BYTES)
    nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
    session_key = derive_aes_key(
        mode,
        salt,
        aad=aad,
        bb84_key_bits=bb84_key_bits,
        mlkem_secret=mlkem_secret,
    )
    ciphertext = AESGCM(session_key).encrypt(nonce, message.encode("utf-8"), aad)
    return EncryptedMessage(ciphertext=ciphertext, nonce=nonce, salt=salt, aad=aad, mode=mode)


def decrypt_message(enc: EncryptedMessage, receiver_key_bits: list[int]) -> str:
    """Authenticate and decrypt a message using Bob's independent BB84 key copy."""
    return decrypt_message_with_secrets(enc, bb84_key_bits=receiver_key_bits)


def decrypt_message_with_secrets(
    enc: EncryptedMessage,
    *,
    bb84_key_bits: list[int] | None = None,
    mlkem_secret: bytes | None = None,
) -> str:
    """Authenticate and decrypt using the receiver's mode-specific secret material."""
    try:
        session_key = derive_aes_key(
            enc.mode,
            enc.salt,
            aad=enc.aad,
            bb84_key_bits=bb84_key_bits,
            mlkem_secret=mlkem_secret,
        )
        plaintext = AESGCM(session_key).decrypt(enc.nonce, enc.ciphertext, enc.aad)
        return plaintext.decode("utf-8")
    except (InvalidTag, UnicodeDecodeError, ValueError) as exc:
        raise DecryptionError(
            "Message authentication or decryption failed; the receiver key or ciphertext may be incorrect."
        ) from exc


def send_secure_message(
    bb84_result: Any,
    message: str,
    min_key_bits: int = MIN_KEY_BITS,
    *,
    aad: bytes = DEFAULT_AAD,
    mode: str = "bb84",
    mlkem_secret: bytes | None = None,
) -> EncryptedMessage:
    """Validate required material and encrypt the sender's actual message."""
    alice_key: list[int] | None = None
    if mode in ("bb84", "hybrid"):
        check_key_usable(bb84_result, min_key_bits=min_key_bits)
        alice_key = _alice_key(bb84_result)
    return encrypt_message_with_secrets(
        message,
        mode,
        bb84_key_bits=alice_key,
        mlkem_secret=mlkem_secret,
        aad=aad,
    )


def receive_secure_message(
    bb84_result: Any,
    enc: EncryptedMessage,
    *,
    mlkem_secret: bytes | None = None,
) -> str:
    """Decrypt using Bob's own BB84 and/or ML-KEM secret copy."""
    bob_key: list[int] | None = None
    if enc.mode in ("bb84", "hybrid"):
        check_key_usable(bb84_result, min_key_bits=0)
        bob_key = _bob_key(bb84_result)
    return decrypt_message_with_secrets(
        enc,
        bb84_key_bits=bob_key,
        mlkem_secret=mlkem_secret,
    )
