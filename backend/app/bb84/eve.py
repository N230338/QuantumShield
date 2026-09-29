"""Simulated intercept-and-resend attacker for the BB84 prototype.

Eve is a simulated attacker in the classical QKD model, not a cryptographic algorithm.
Her effect is explained by the measurement basis mismatch: when Eve chooses a different basis
from Alice, her measurement result is random. Because she resends a state encoded in her own
basis, Bob later measures in Alice's basis and can obtain the wrong bit with probability 50%.
Thus for full interception the expected sifted-bit error probability is 0.5 x 0.5 = 25%.
This simulation uses Aer to run the actual quantum circuits for Eve's measurement and
re-preparation; there is no real photon channel or physical network.
"""

from __future__ import annotations

from typing import Optional

import numpy as np
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator

from backend.app.bb84.circuits import build_qubit_circuit

_AER_SIMULATOR = AerSimulator()


def _safe_memory_bit(memory_value: object) -> int:
    if isinstance(memory_value, str):
        value = memory_value.strip()
        if value.startswith("0x"):
            return int(value, 16) & 1
        if value:
            return int(value[-1])
        return 0
    if isinstance(memory_value, (int, np.integer)):
        return int(memory_value) & 1
    if isinstance(memory_value, list):
        return _safe_memory_bit(memory_value[0]) if memory_value else 0
    return int(str(memory_value)[-1])


def _validate_intercept_fraction(intercept_fraction: float) -> None:
    if not 0.0 <= intercept_fraction <= 1.0:
        raise ValueError("intercept_fraction must be in the range [0, 1].")


def run_two_stage_eve(
    alice_bits: list[int],
    alice_bases: list[str],
    bob_bases: list[str],
    intercept_fraction: float = 1.0,
    seed: Optional[int] = None,
    noise_flips: list[bool] | None = None,
) -> tuple[list[int], list[str | None], list[int | None], list[bool]]:
    """Simulate Eve's intercept-and-resend using two Aer batches.

    Stage 1: Alice prepares each intercepted qubit and Eve measures in her own basis.
    Stage 2: Eve re-prepares the measured bit in her basis and Bob measures it in his basis.
    Non-intercepted positions pass directly from Alice to Bob with the normal per-qubit path.
    """
    _validate_intercept_fraction(intercept_fraction)
    n_qubits = len(alice_bits)
    rng = np.random.default_rng(seed)
    if noise_flips is None:
        noise_flips = [False] * n_qubits

    intercepted_mask = [bool(rng.random() < intercept_fraction) for _ in range(n_qubits)]
    eve_bases: list[str | None] = [None] * n_qubits
    eve_bits: list[int | None] = [None] * n_qubits
    bob_bits: list[int] = [0] * n_qubits

    if not any(intercepted_mask):
        normal_circuits = [
            build_qubit_circuit(
                alice_bits[idx], alice_bases[idx], bob_bases[idx], noise_flip=noise_flips[idx]
            )
            for idx in range(n_qubits)
        ]
        normal_result = _AER_SIMULATOR.run(
            normal_circuits,
            shots=1,
            memory=True,
            seed_simulator=seed if seed is not None else 1234,
        ).result()
        for run_index in range(len(normal_circuits)):
            memory_value = normal_result.get_memory(run_index)[0]
            bob_bits[run_index] = _safe_memory_bit(memory_value)
        return bob_bits, eve_bases, eve_bits, intercepted_mask

    stage1_circuits: list[QuantumCircuit] = []
    stage1_indices: list[int] = []
    for idx in range(n_qubits):
        if not intercepted_mask[idx]:
            continue
        eve_basis = "Z" if rng.integers(0, 2) == 0 else "X"
        eve_bases[idx] = eve_basis
        circuit = QuantumCircuit(1, 1)
        if alice_bits[idx] == 1:
            circuit.x(0)
        if alice_bases[idx] == "X":
            circuit.h(0)
        if eve_basis == "X":
            circuit.h(0)
        circuit.measure(0, 0)
        stage1_circuits.append(circuit)
        stage1_indices.append(idx)

    if stage1_circuits:
        stage1_result = _AER_SIMULATOR.run(
            stage1_circuits,
            shots=1,
            memory=True,
            seed_simulator=seed if seed is not None else 1234,
        ).result()
        for run_index, idx in enumerate(stage1_indices):
            eve_bits[idx] = _safe_memory_bit(stage1_result.get_memory(run_index)[0])

    normal_circuits: list[QuantumCircuit] = []
    normal_indices: list[int] = []
    for idx in range(n_qubits):
        if intercepted_mask[idx]:
            continue
        normal_circuits.append(
            build_qubit_circuit(
                alice_bits[idx], alice_bases[idx], bob_bases[idx], noise_flip=noise_flips[idx]
            )
        )
        normal_indices.append(idx)

    if normal_circuits:
        normal_result = _AER_SIMULATOR.run(
            normal_circuits,
            shots=1,
            memory=True,
            seed_simulator=seed if seed is not None else 1234,
        ).result()
        for run_index, idx in enumerate(normal_indices):
            bob_bits[idx] = _safe_memory_bit(normal_result.get_memory(run_index)[0])

    if any(intercepted_mask):
        stage2_circuits: list[QuantumCircuit] = []
        stage2_indices: list[int] = []
        for idx in range(n_qubits):
            if not intercepted_mask[idx]:
                continue
            eve_bit = eve_bits[idx]
            eve_basis = eve_bases[idx]
            assert eve_bit is not None and eve_basis is not None
            circuit = QuantumCircuit(1, 1)
            if eve_bit == 1:
                circuit.x(0)
            if eve_basis == "X":
                circuit.h(0)
            if bob_bases[idx] == "X":
                circuit.h(0)
            if noise_flips[idx]:
                circuit.x(0)
            circuit.measure(0, 0)
            stage2_circuits.append(circuit)
            stage2_indices.append(idx)

        if stage2_circuits:
            stage2_result = _AER_SIMULATOR.run(
                stage2_circuits,
                shots=1,
                memory=True,
                seed_simulator=seed if seed is not None else 1234,
            ).result()
            for run_index, idx in enumerate(stage2_indices):
                bob_bits[idx] = _safe_memory_bit(stage2_result.get_memory(run_index)[0])

    return bob_bits, eve_bases, eve_bits, intercepted_mask
