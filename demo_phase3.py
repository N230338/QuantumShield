"""Phase 3 demonstration for the Aer-backed BB84 simulator."""

import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from backend.app.bb84.circuits import build_display_circuit, circuit_to_text
from backend.app.bb84.core import run_bb84_qiskit


def main() -> None:
    result = run_bb84_qiskit(20, seed=42)

    print("Alice bits:", result["alice_bits"])
    print("Alice bases:", result["alice_bases"])
    print("Bob bases:", result["bob_bases"])
    print("Bob bits:", result["bob_bits"])
    print("Matching positions:", result["matching_positions"])
    print("Sifted key:", result["sifted_key"])
    print("QBER sample:", result["qber"])
    print("Decision:", result["decision"])

    first_n = min(8, len(result["alice_bits"]))
    display = build_display_circuit(
        result["alice_bits"][:first_n],
        result["alice_bases"][:first_n],
        result["bob_bases"][:first_n],
        max_qubits=first_n,
    )
    print("\nCircuit drawing for the first 8 qubits:")
    print(circuit_to_text(display))


if __name__ == "__main__":
    main()
