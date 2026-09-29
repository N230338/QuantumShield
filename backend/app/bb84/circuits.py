"""Quantum circuit helpers for the BB84 simulation.

This module encodes the exact gate rules required by the project specification:
- Basis "Z" (+): bit 0 -> |0>, bit 1 -> |1>
- Basis "X" (X): bit 0 -> |+>, bit 1 -> |->
- Alice prep: start |0>; if bit == 1 apply X; if basis == X apply H
- Bob measure: if Bob basis == X apply H, then measure in the computational basis.

The circuit-building code intentionally mirrors the logic executed by the Aer simulator;
there is no real quantum hardware or network involved.
"""

from __future__ import annotations

import base64
import io

from qiskit import QuantumCircuit


def build_qubit_circuit(
    alice_bit: int,
    alice_basis: str,
    bob_basis: str,
    noise_flip: bool = False,
) -> QuantumCircuit:
    """Build the 1-qubit, 1-classical-bit circuit used for each BB84 transmission.

    Qiskit uses little-endian bit-ordering; for a single qubit this remains straightforward,
    but the circuit is intentionally kept to the same qubit semantics as the project notes.
    """
    if alice_bit not in (0, 1):
        raise ValueError("alice_bit must be 0 or 1.")
    if alice_basis not in {"Z", "X"} or bob_basis not in {"Z", "X"}:
        raise ValueError("Alice and Bob bases must be 'Z' or 'X'.")

    circuit = QuantumCircuit(1, 1)
    if alice_bit == 1:
        circuit.x(0)
    if alice_basis == "X":
        circuit.h(0)
    circuit.barrier(0)
    if bob_basis == "X":
        circuit.h(0)
    if noise_flip:
        circuit.x(0)
    circuit.measure(0, 0)
    return circuit


def build_preparation_circuit(bit: int, basis: str) -> QuantumCircuit:
    """Return Alice's preparation circuit only, without any measurement gate."""
    if bit not in (0, 1):
        raise ValueError("bit must be 0 or 1.")
    if basis not in {"Z", "X"}:
        raise ValueError("basis must be 'Z' or 'X'.")

    circuit = QuantumCircuit(1)
    if bit == 1:
        circuit.x(0)
    if basis == "X":
        circuit.h(0)
    return circuit


def build_display_circuit(
    alice_bits: list[int],
    alice_bases: list[str],
    bob_bases: list[str],
    max_qubits: int = 12,
) -> QuantumCircuit:
    """Create a single multi-qubit display circuit for a few representative positions."""
    if len(alice_bits) != len(alice_bases) or len(alice_bits) != len(bob_bases):
        raise ValueError("Alice bits and bases arrays must have the same length.")
    if max_qubits <= 0:
        raise ValueError("max_qubits must be a positive integer.")

    n_qubits = min(len(alice_bits), max_qubits)
    circuit = QuantumCircuit(n_qubits, n_qubits)
    for idx in range(n_qubits):
        if alice_bits[idx] == 1:
            circuit.x(idx)
        if alice_bases[idx] == "X":
            circuit.h(idx)
        circuit.barrier(idx)
        if bob_bases[idx] == "X":
            circuit.h(idx)
        circuit.measure(idx, idx)
    return circuit


def build_attack_display_circuit(
    alice_bits: list[int],
    alice_bases: list[str],
    eve_bases: list[str | None],
    bob_bases: list[str],
    max_qubits: int = 8,
) -> QuantumCircuit:
    """Create a visual circuit for the Eve interception stage.

    This is a display-only aid: the actual attack logic uses a two-stage Aer simulation in
    `backend.app.bb84.eve`, where Eve measures, re-prepares, and Bob measures again. This
    circuit is intended to visualize the conceptual flow, not to claim literal execution of
    the exact identical gated sequence shown here.
    """
    if len(alice_bits) != len(alice_bases) or len(alice_bits) != len(bob_bases):
        raise ValueError("Alice and Bob arrays must have the same length.")
    if max_qubits <= 0:
        raise ValueError("max_qubits must be a positive integer.")

    n_qubits = min(len(alice_bits), max_qubits)
    circuit = QuantumCircuit(n_qubits, n_qubits)
    for idx in range(n_qubits):
        if alice_bits[idx] == 1:
            circuit.x(idx)
        if alice_bases[idx] == "X":
            circuit.h(idx)
        circuit.barrier(idx)
        if eve_bases[idx] == "X":
            circuit.h(idx)
        circuit.barrier(idx)
        if bob_bases[idx] == "X":
            circuit.h(idx)
        circuit.measure(idx, idx)
    return circuit


def circuit_to_text(circuit: QuantumCircuit) -> str:
    """Return the text-formatted circuit drawing from Qiskit."""
    return str(circuit.draw(output="text", fold=80))


def circuit_to_png_base64(circuit: QuantumCircuit) -> str:
    """Return a PNG for the circuit as a base64-encoded string."""
    import matplotlib

    matplotlib.use("Agg")
    from matplotlib import pyplot as plt

    figure = circuit.draw(output="mpl")
    buffer = io.BytesIO()
    figure.savefig(buffer, format="png", dpi=150)
    plt.close(figure)
    return base64.b64encode(buffer.getvalue()).decode("ascii")
