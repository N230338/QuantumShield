from __future__ import annotations

import base64
import pytest

from qiskit import QuantumCircuit
from qiskit.quantum_info import Statevector

from backend.app.bb84.circuits import (
    build_display_circuit,
    build_preparation_circuit,
    build_qubit_circuit,
    circuit_to_png_base64,
    circuit_to_text,
)
from backend.app.bb84.core import QBERDecision, run_bb84, run_bb84_qiskit


def _execute_single_qubit(circuit: QuantumCircuit) -> int:
    from qiskit_aer import AerSimulator

    sim = AerSimulator()
    result = sim.run(circuit, shots=1, memory=True).result()
    return int(result.get_memory()[0], 2)


def test_statevector_encoding_matches_expected_states():
    expected = {
        (0, "Z"): Statevector.from_label("0"),
        (1, "Z"): Statevector.from_label("1"),
        (0, "X"): Statevector.from_label("+") ,
        (1, "X"): Statevector.from_label("-") ,
    }

    for (bit, basis), expected_state in expected.items():
        circuit = build_preparation_circuit(bit, basis)
        actual = Statevector(circuit)
        assert actual.equiv(expected_state)


def test_same_basis_same_bit_for_all_combinations_and_random_sample():
    for bit in (0, 1):
        for basis in ("Z", "X"):
            circuit = build_qubit_circuit(bit, basis, basis)
            bob_bit = _execute_single_qubit(circuit)
            assert bob_bit == bit

    result = run_bb84_qiskit(200, seed=17)
    for idx in range(len(result["alice_bits"])):
        if result["matching_mask"][idx]:
            assert result["alice_bits"][idx] == result["bob_bits"][idx]


def test_different_bases_give_about_half_match_fraction():
    result = run_bb84_qiskit(256, seed=25)
    total = sum(1 for idx in range(len(result["alice_bits"])) if result["alice_bases"][idx] != result["bob_bases"][idx])
    equal_count = sum(
        1
        for idx in range(len(result["alice_bits"]))
        if result["alice_bases"][idx] != result["bob_bases"][idx] and result["alice_bits"][idx] == result["bob_bits"][idx]
    )
    fraction = equal_count / total if total else 0.0
    assert 0.45 <= fraction <= 0.55


@pytest.mark.slow
def test_qiskit_bb84_run_accepts_without_attack_and_reproduces_seed():
    result = run_bb84_qiskit(256, seed=7)

    assert result["qber"] == 0.0
    assert result["decision"] == QBERDecision.ACCEPTED
    assert 0.5 * 256 * 0.85 <= result["sifted_length"] <= 0.5 * 256 * 1.15
    result_2 = run_bb84_qiskit(256, seed=7)
    assert result["bob_bits"] == result_2["bob_bits"]
    assert result["final_key"] == result_2["final_key"]


def test_qiskit_result_matches_phase1_sifting_logic():
    result = run_bb84_qiskit(128, seed=123)
    expected_mask = [a == b for a, b in zip(result["alice_bases"], result["bob_bases"])]
    assert result["matching_mask"] == expected_mask
    assert result["matching_positions"] == [idx for idx, match in enumerate(expected_mask) if match]


@pytest.mark.slow
def test_display_circuit_and_png_generation():
    display = build_display_circuit([0, 1, 0, 1, 0, 1], ["Z", "X", "Z", "X", "Z", "X"], ["Z", "Z", "X", "X", "Z", "X"], max_qubits=12)
    assert display.num_qubits == 6
    text = circuit_to_text(display)
    assert text.strip()
    png_b64 = circuit_to_png_base64(display)
    assert png_b64
    decoded = base64.b64decode(png_b64)
    assert decoded.startswith(b"\x89PNG\r\n\x1a\n")


def test_qiskit_n_qubits_validation():
    try:
        run_bb84_qiskit(7, seed=1)
        raise AssertionError("Expected ValueError for n_qubits below minimum")
    except ValueError:
        pass

    try:
        run_bb84_qiskit(513, seed=1)
        raise AssertionError("Expected ValueError for n_qubits above maximum")
    except ValueError:
        pass
