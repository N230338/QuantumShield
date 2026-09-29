"""Pure-Python BB84 key-establishment logic plus a Qiskit/Aer simulation runner.

Encoding convention used by this prototype:
- Basis "Z" (rectilinear, shown as "+"): bit 0 -> |0>, bit 1 -> |1>
- Basis "X" (diagonal, shown as "X"): bit 0 -> |+>, bit 1 -> |->
- Alice prepares: start |0>; if bit == 1 apply X; if basis == X apply H
- Measuring in basis Z: measure directly. Measuring in basis X: apply H then measure.

This module intentionally handles the classical key-establishment flow and the
Aer-based circuit simulation. It does not encrypt the message itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

import numpy as np
from qiskit_aer import AerSimulator

from backend.app.bb84.circuits import build_qubit_circuit
from backend.app.bb84.eve import run_two_stage_eve

_AER_SIMULATOR = AerSimulator()


class QBERDecision(str, Enum):
    """Possible outcomes of the BB84 security decision."""

    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"


VALID_BASES = {"Z", "X"}


@dataclass
class BB84Result:
    """Dictionary-like container for a BB84 run result.

    The result is intentionally dict-like so the earlier Phase 1 tests and the Qiskit
    simulation can share the same access pattern (result["alice_bits"]).
    """

    alice_bits: list[int]
    alice_bases: list[str]
    bob_bases: list[str]
    bob_bits: list[int]
    matching_positions: list[int]
    matching_mask: list[bool]
    sifted_positions: list[int]
    final_key: list[int]
    alice_final_key: list[int]
    bob_sifted_key: list[int]
    bob_final_key: list[int]
    qber: float
    sample_size: int
    sampled_positions: list[int]
    decision: QBERDecision
    reason: str
    final_key_length: int = 0
    sifted_length: int = 0
    attack_enabled: bool = False
    intercept_fraction: float | None = None
    eve_bases: list[str | None] | None = None
    eve_bits: list[int | None] | None = None
    intercepted_mask: list[bool] | None = None
    errors_in_sifted_key: int = 0
    qber_sample_qber: float = 0.0
    qber_full_sifted: float = 0.0
    key_status: str = "INSUFFICIENT_DATA"
    interception_flag: bool = False

    @property
    def sifted_key(self) -> list[int]:
        return self.final_key

    def __getitem__(self, key: str):
        return getattr(self, key)


def _new_rng(seed: Optional[int] = None):
    if seed is None:
        return None
    return np.random.default_rng(seed)


def _random_bit(rng: Optional[np.random.Generator] = None) -> int:
    if rng is None:
        return int(np.random.randint(0, 2))
    return int(rng.integers(0, 2))


def _random_basis(rng: Optional[np.random.Generator] = None) -> str:
    return "Z" if _random_bit(rng) == 0 else "X"


def _validate_n_qubits(n_qubits: int, minimum: int = 1, maximum: Optional[int] = None) -> None:
    if not isinstance(n_qubits, int) or not minimum <= n_qubits:
        raise ValueError(f"n_qubits must be an integer >= {minimum}.")
    if maximum is not None and n_qubits > maximum:
        raise ValueError(f"n_qubits must be <= {maximum}.")


def generate_bits(n_qubits: int, seed: Optional[int] = None) -> list[int]:
    """Return an array of n_qubits random bits with reproducible seeding."""
    _validate_n_qubits(n_qubits, minimum=1)
    rng = _new_rng(seed)
    return [_random_bit(rng) for _ in range(n_qubits)]


def generate_bases(n_qubits: int, seed: Optional[int] = None) -> list[str]:
    """Return an array of Alice/Bob random measurement bases."""
    _validate_n_qubits(n_qubits, minimum=1)
    rng = _new_rng(seed)
    return [_random_basis(rng) for _ in range(n_qubits)]


def sift_positions(alice_bases: list[str], bob_bases: list[str]) -> list[int]:
    """Return positions where Alice and Bob selected the same basis."""
    if len(alice_bases) != len(bob_bases):
        raise ValueError("Alice and Bob basis lists must have the same length.")
    return [idx for idx, (a, b) in enumerate(zip(alice_bases, bob_bases)) if a == b]


def _apply_noise(bit: int, noise_probability: float, rng: Optional[np.random.Generator]) -> int:
    if noise_probability <= 0.0:
        return bit
    if rng is None:
        if np.random.random() < noise_probability:
            return 1 - bit
        return bit
    if rng.random() < noise_probability:
        return 1 - bit
    return bit


def _simulate_measurement(alice_bit: int, alice_basis: str, bob_basis: str, rng: Optional[np.random.Generator]) -> int:
    """Simulate the BB84 measurement process in the classical domain.

    If both parties choose the same basis, the result is the original prepared bit.
    If they choose different bases, the outcome is random because the measurement basis is
    mismatched, which is exactly the source of the expected 25% QBER under interception.
    """
    if alice_basis not in VALID_BASES or bob_basis not in VALID_BASES:
        raise ValueError("Bases must be either 'Z' or 'X'.")
    if alice_basis == bob_basis:
        return alice_bit
    return _random_bit(rng)


def _choose_sample_positions(positions: list[int], sample_fraction: float, rng: Optional[np.random.Generator]) -> list[int]:
    if not 0.0 <= sample_fraction <= 1.0:
        raise ValueError("qber_sample_fraction must be between 0.0 and 1.0.")
    if not positions:
        return []
    sample_size = max(1, int(round(len(positions) * sample_fraction)))
    sample_size = min(sample_size, len(positions))
    if rng is None:
        sampled = list(np.random.choice(positions, size=sample_size, replace=False))
    else:
        sampled = list(rng.choice(positions, size=sample_size, replace=False))
    return sorted(sampled)


def run_bb84(
    n_qubits: int,
    attack: bool = False,
    intercept_fraction: float = 1.0,
    qber_sample_fraction: float = 0.25,
    qber_threshold: float = 0.11,
    noise_probability: float = 0.0,
    seed: Optional[int] = None,
) -> dict:
    """Execute a single BB84 run in the pure-Python simulation.

    Returns a summary dictionary containing all bit/basis arrays, matching positions,
    the sifted key, QBER information, and the final security decision.
    """
    _validate_n_qubits(n_qubits, minimum=1)
    if not 0.0 <= intercept_fraction <= 1.0:
        raise ValueError("intercept_fraction must be between 0.0 and 1.0.")
    if not 0.0 <= qber_sample_fraction <= 1.0:
        raise ValueError("qber_sample_fraction must be between 0.0 and 1.0.")
    if not 0.0 <= noise_probability <= 1.0:
        raise ValueError("noise_probability must be between 0.0 and 1.0.")

    rng = _new_rng(seed)
    alice_bits = generate_bits(n_qubits, seed=seed)
    alice_bases = generate_bases(n_qubits, seed=seed + 1 if seed is not None else None)
    bob_bases = generate_bases(n_qubits, seed=seed + 2 if seed is not None else None)
    bob_bits: list[int] = []

    for idx in range(n_qubits):
        alice_bit = alice_bits[idx]
        alice_basis = alice_bases[idx]
        bob_basis = bob_bases[idx]

        if attack and idx < int(round(n_qubits * intercept_fraction)):
            eve_basis = _random_basis(rng)
            eve_measurement = _simulate_measurement(alice_bit, alice_basis, eve_basis, rng)
            bob_bit = _simulate_measurement(eve_measurement, eve_basis, bob_basis, rng)
        else:
            bob_bit = _simulate_measurement(alice_bit, alice_basis, bob_basis, rng)

        bob_bit = _apply_noise(bob_bit, noise_probability, rng)
        bob_bits.append(bob_bit)

    matching_positions = sift_positions(alice_bases, bob_bases)
    if not matching_positions:
        return {
            "alice_bits": alice_bits,
            "alice_bases": alice_bases,
            "bob_bases": bob_bases,
            "bob_bits": bob_bits,
            "matching_positions": matching_positions,
            "matching_mask": [a == b for a, b in zip(alice_bases, bob_bases)],
            "sifted_positions": matching_positions,
            "sifted_key": [],
            "sifted_length": 0,
            "final_key_length": 0,
            "qber": 0.0,
            "sample_size": 0,
            "decision": QBERDecision.INSUFFICIENT_DATA,
            "reason": "No matching bases were found; insufficient data to continue. Increase the number of qubits or adjust the sample settings.",
        }

    sample_size = max(1, int(round(len(matching_positions) * qber_sample_fraction)))
    if sample_size < 8:
        return {
            "alice_bits": alice_bits,
            "alice_bases": alice_bases,
            "bob_bases": bob_bases,
            "bob_bits": bob_bits,
            "matching_positions": matching_positions,
            "matching_mask": [a == b for a, b in zip(alice_bases, bob_bases)],
            "sifted_positions": matching_positions,
            "sifted_key": [bob_bits[idx] for idx in matching_positions],
            "sifted_length": len(matching_positions),
            "final_key_length": len([bob_bits[idx] for idx in matching_positions]),
            "qber": 0.0,
            "sample_size": sample_size,
            "decision": QBERDecision.INSUFFICIENT_DATA,
            "reason": "Insufficient data: the QBER sample would be too small (< 8 bits); increase the number of qubits to gather sufficient data.",
        }

    sampled_positions = _choose_sample_positions(matching_positions, qber_sample_fraction, rng)
    sampled_mismatches = sum(1 for idx in sampled_positions if alice_bits[idx] != bob_bits[idx])
    qber = sampled_mismatches / len(sampled_positions)
    remaining_positions = [idx for idx in matching_positions if idx not in sampled_positions]
    final_key = [bob_bits[idx] for idx in remaining_positions]

    if qber <= qber_threshold:
        decision = QBERDecision.ACCEPTED
        reason = (
            f"QBER = {qber:.3f} is within the configured threshold of {qber_threshold:.3f}; "
            "the BB84 key is accepted."
        )
    else:
        decision = QBERDecision.REJECTED
        reason = (
            f"QBER = {qber:.3f} exceeds the configured threshold of {qber_threshold:.3f}; "
            "possible interception or channel noise detected."
        )

    return {
        "alice_bits": alice_bits,
        "alice_bases": alice_bases,
        "bob_bases": bob_bases,
        "bob_bits": bob_bits,
        "matching_positions": matching_positions,
        "matching_mask": [a == b for a, b in zip(alice_bases, bob_bases)],
        "sifted_positions": matching_positions,
        "sifted_key": final_key,
        "sifted_length": len(matching_positions),
        "final_key_length": len(final_key),
        "sampled_positions": sampled_positions,
        "sample_size": len(sampled_positions),
        "qber": qber,
        "decision": decision,
        "reason": reason,
    }


def run_bb84_qiskit(
    n_qubits: int,
    seed: Optional[int] = None,
    qber_sample_fraction: float = 0.25,
    qber_threshold: float = 0.11,
    attack: bool = False,
    intercept_fraction: float = 1.0,
    noise_probability: float = 0.0,
) -> BB84Result:
    """Execute BB84 with real Aer-based measurement, optionally with Eve interception.

    The simulator derives Bob's bits solely from `AerSimulator` measurement outputs. A high
    QBER is consistent with Eve but does not prove that Eve is the only possible cause, which
    is why the decision reasons are phrased as possible interception or channel noise.
    """
    _validate_n_qubits(n_qubits, minimum=8, maximum=512)
    if not 0.0 <= qber_sample_fraction <= 1.0:
        raise ValueError("qber_sample_fraction must be between 0.0 and 1.0.")
    if not 0.0 <= intercept_fraction <= 1.0:
        raise ValueError("intercept_fraction must be in the range [0, 1].")
    if not 0.0 <= noise_probability <= 1.0:
        raise ValueError("noise_probability must be between 0.0 and 1.0.")

    rng = _new_rng(seed)
    alice_bits = generate_bits(n_qubits, seed=seed)
    alice_bases = generate_bases(n_qubits, seed=seed + 1 if seed is not None else None)
    bob_bases = generate_bases(n_qubits, seed=seed + 2 if seed is not None else None)
    noise_rng = np.random.default_rng(seed + 3 if seed is not None else None)
    noise_flips = [bool(noise_rng.random() < noise_probability) for _ in range(n_qubits)]

    if not attack:
        circuits = [
            build_qubit_circuit(
                alice_bits[idx], alice_bases[idx], bob_bases[idx], noise_flip=noise_flips[idx]
            )
            for idx in range(n_qubits)
        ]
        result = _AER_SIMULATOR.run(
            circuits,
            shots=1,
            memory=True,
            seed_simulator=seed if seed is not None else 1234,
        ).result()

        bob_bits: list[int] = []
        for idx in range(len(circuits)):
            memory_result = result.get_memory(idx)
            bitstring = memory_result[0]
            if isinstance(bitstring, str) and bitstring.startswith("0x"):
                bob_bits.append(int(bitstring, 16) & 1)
            else:
                bob_bits.append(int(str(bitstring)[-1]))

        eve_bases = None
        eve_bits = None
        intercepted_mask = None
    else:
        bob_bits, eve_bases, eve_bits, intercepted_mask = run_two_stage_eve(
            alice_bits=alice_bits,
            alice_bases=alice_bases,
            bob_bases=bob_bases,
            intercept_fraction=intercept_fraction,
            seed=seed,
            noise_flips=noise_flips,
        )

    matching_positions = sift_positions(alice_bases, bob_bases)
    matching_mask = [alice_bases[idx] == bob_bases[idx] for idx in range(n_qubits)]
    bob_sifted_key = [bob_bits[idx] for idx in matching_positions]
    alice_sifted_key = [alice_bits[idx] for idx in matching_positions]
    errors_in_sifted_key = sum(1 for a, b in zip(alice_sifted_key, bob_sifted_key) if a != b)
    qber_full_sifted = (errors_in_sifted_key / len(matching_positions)) if matching_positions else 0.0

    if not matching_positions:
        return BB84Result(
            alice_bits=alice_bits,
            alice_bases=alice_bases,
            bob_bases=bob_bases,
            bob_bits=bob_bits,
            matching_positions=[],
            matching_mask=matching_mask,
            sifted_positions=[],
            final_key=[],
            alice_final_key=[],
            bob_sifted_key=[],
            bob_final_key=[],
            qber=0.0,
            sample_size=0,
            sampled_positions=[],
            decision=QBERDecision.INSUFFICIENT_DATA,
            reason="Sample too small for a reliable decision; increase the number of qubits",
            final_key_length=0,
            sifted_length=0,
            attack_enabled=attack,
            intercept_fraction=intercept_fraction if attack else 0.0,
            eve_bases=eve_bases if attack else None,
            eve_bits=eve_bits if attack else None,
            intercepted_mask=intercepted_mask if attack else None,
            errors_in_sifted_key=0,
            qber_sample_qber=0.0,
            qber_full_sifted=qber_full_sifted,
            key_status=QBERDecision.INSUFFICIENT_DATA.value,
            interception_flag=False,
        )

    sample_size = max(1, int(round(len(matching_positions) * qber_sample_fraction)))
    if sample_size < 8:
        return BB84Result(
            alice_bits=alice_bits,
            alice_bases=alice_bases,
            bob_bases=bob_bases,
            bob_bits=bob_bits,
            matching_positions=matching_positions,
            matching_mask=matching_mask,
            sifted_positions=matching_positions,
            final_key=bob_sifted_key,
            alice_final_key=alice_sifted_key,
            bob_sifted_key=bob_sifted_key,
            bob_final_key=bob_sifted_key,
            qber=0.0,
            sample_size=sample_size,
            sampled_positions=[],
            decision=QBERDecision.INSUFFICIENT_DATA,
            reason="Sample too small for a reliable decision; increase the number of qubits",
            final_key_length=len(bob_sifted_key),
            sifted_length=len(matching_positions),
            attack_enabled=attack,
            intercept_fraction=intercept_fraction if attack else 0.0,
            eve_bases=eve_bases if attack else None,
            eve_bits=eve_bits if attack else None,
            intercepted_mask=intercepted_mask if attack else None,
            errors_in_sifted_key=errors_in_sifted_key,
            qber_sample_qber=0.0,
            qber_full_sifted=qber_full_sifted,
            key_status=QBERDecision.INSUFFICIENT_DATA.value,
            interception_flag=False,
        )

    sampled_positions = _choose_sample_positions(matching_positions, qber_sample_fraction, rng)
    sampled_mismatches = sum(1 for idx in sampled_positions if alice_bits[idx] != bob_bits[idx])
    qber = sampled_mismatches / len(sampled_positions)
    remaining_positions = [idx for idx in matching_positions if idx not in sampled_positions]
    final_key = [bob_bits[idx] for idx in remaining_positions]
    alice_final_key = [alice_bits[idx] for idx in remaining_positions]

    if qber <= qber_threshold:
        decision = QBERDecision.ACCEPTED
        reason = "QBER within threshold; key accepted"
    else:
        decision = QBERDecision.REJECTED
        reason = "QBER above threshold: possible interception (or channel noise); key rejected"

    return BB84Result(
        alice_bits=alice_bits,
        alice_bases=alice_bases,
        bob_bases=bob_bases,
        bob_bits=bob_bits,
        matching_positions=matching_positions,
        matching_mask=matching_mask,
        sifted_positions=matching_positions,
        final_key=final_key,
        alice_final_key=alice_final_key,
        bob_sifted_key=bob_sifted_key,
        bob_final_key=final_key,
        qber=qber,
        sample_size=len(sampled_positions),
        sampled_positions=sampled_positions,
        decision=decision,
        reason=reason,
        final_key_length=len(final_key),
        sifted_length=len(matching_positions),
        attack_enabled=attack,
        intercept_fraction=intercept_fraction if attack else 0.0,
        eve_bases=eve_bases if attack else None,
        eve_bits=eve_bits if attack else None,
        intercepted_mask=intercepted_mask if attack else None,
        errors_in_sifted_key=errors_in_sifted_key,
        qber_sample_qber=qber,
        qber_full_sifted=qber_full_sifted,
        key_status=decision.value,
        interception_flag=decision == QBERDecision.REJECTED,
    )
