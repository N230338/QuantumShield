"""NIST ML-KEM-768 key establishment through the pqcrypto Rust bindings."""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field

from pqcrypto.kem import ml_kem_768


class PQCError(ValueError):
    """Raised for invalid ML-KEM inputs or failed key agreement."""


@dataclass(frozen=True)
class MLKEMKeyPair:
    """Ephemeral ML-KEM recipient keypair; secret material is hidden from repr."""

    public_key: bytes
    private_key: bytes = field(repr=False)


@dataclass(frozen=True)
class MLKEMEncapsulation:
    """Sender-side ciphertext and shared secret from one encapsulation."""

    ciphertext: bytes
    shared_secret: bytes = field(repr=False)


@dataclass(frozen=True)
class MLKEMExchange:
    """In-process sender/receiver agreement used by the communication simulation."""

    ciphertext: bytes
    sender_secret: bytes = field(repr=False)
    receiver_secret: bytes = field(repr=False)


class MLKEM768Provider:
    """FIPS 203 ML-KEM-768 provider; no pre-standard Kyber algorithms are used."""

    name = "ML-KEM-768"
    status = "IMPLEMENTED"

    def keygen(self) -> MLKEMKeyPair:
        """Generate fresh recipient public/private key material."""
        try:
            public_key, private_key = ml_kem_768.keygen()
        except ValueError as exc:
            raise PQCError("ML-KEM-768 key generation failed.") from exc
        if len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
            raise PQCError("ML-KEM-768 returned an invalid public key.")
        if len(private_key) != ml_kem_768.SECRET_KEY_SIZE:
            raise PQCError("ML-KEM-768 returned an invalid private key.")
        return MLKEMKeyPair(public_key=public_key, private_key=private_key)

    def encapsulate(self, public_key: bytes) -> MLKEMEncapsulation:
        """Encapsulate a fresh shared secret to a validated ML-KEM public key."""
        if not isinstance(public_key, bytes) or len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
            raise PQCError("ML-KEM-768 public key has an invalid type or length.")
        try:
            ciphertext, shared_secret = ml_kem_768.encaps(public_key)
        except ValueError as exc:
            raise PQCError("ML-KEM-768 encapsulation failed.") from exc
        if len(ciphertext) != ml_kem_768.CIPHERTEXT_SIZE:
            raise PQCError("ML-KEM-768 returned an invalid ciphertext.")
        if len(shared_secret) != ml_kem_768.SHARED_SECRET_SIZE:
            raise PQCError("ML-KEM-768 returned an invalid shared secret.")
        return MLKEMEncapsulation(ciphertext=ciphertext, shared_secret=shared_secret)

    def decapsulate(self, private_key: bytes, ciphertext: bytes) -> bytes:
        """Recover the shared secret using the matching ML-KEM private key."""
        if not isinstance(private_key, bytes) or len(private_key) != ml_kem_768.SECRET_KEY_SIZE:
            raise PQCError("ML-KEM-768 private key has an invalid type or length.")
        if not isinstance(ciphertext, bytes) or len(ciphertext) != ml_kem_768.CIPHERTEXT_SIZE:
            raise PQCError("ML-KEM-768 ciphertext has an invalid type or length.")
        try:
            shared_secret = ml_kem_768.decaps(private_key, ciphertext)
        except ValueError as exc:
            raise PQCError("ML-KEM-768 decapsulation failed.") from exc
        if len(shared_secret) != ml_kem_768.SHARED_SECRET_SIZE:
            raise PQCError("ML-KEM-768 returned an invalid decapsulated secret.")
        return shared_secret

    def establish_shared_secret(self) -> MLKEMExchange:
        """Simulate sender encapsulation and receiver decapsulation, verifying agreement."""
        key_pair = self.keygen()
        encapsulation = self.encapsulate(key_pair.public_key)
        receiver_secret = self.decapsulate(key_pair.private_key, encapsulation.ciphertext)
        if not hmac.compare_digest(encapsulation.shared_secret, receiver_secret):
            raise PQCError("ML-KEM-768 sender and receiver key agreement failed.")
        return MLKEMExchange(
            ciphertext=encapsulation.ciphertext,
            sender_secret=encapsulation.shared_secret,
            receiver_secret=receiver_secret,
        )


def get_pqc_status() -> dict[str, str | bool]:
    """Return truthful user-facing ML-KEM support status without key material."""
    return {
        "implemented": True,
        "status": "ML-KEM-768 IMPLEMENTED",
        "algorithm": "ML-KEM-768 (NIST FIPS 203)",
        "provider": "pqcrypto Rust bindings",
        "note": "Classical key establishment; not a physical quantum process.",
    }
