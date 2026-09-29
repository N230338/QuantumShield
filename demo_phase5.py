"""Demo script for the Eve intercept-and-resend phase and multi-run statistics."""

from __future__ import annotations

import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from backend.app.bb84.circuits import build_attack_display_circuit, circuit_to_text
from backend.app.bb84.core import run_bb84_qiskit
from backend.app.bb84.experiment import detection_rate_vs_qubits, run_comparison


def _compact(values: list[int] | list[str | None], limit: int = 32) -> str:
    """Format the first positions compactly and show the original total length."""
    compact = "".join("?" if value is None else str(value) for value in values[:limit])
    return f"{compact}{'...' if len(values) > limit else ''} (total={len(values)})"


def _print_run(title: str, result, include_eve: bool = False) -> None:
    """Print a concise view of a BB84 result without dumping full position arrays."""
    print(f"{title}:")
    print("  Alice bits:", _compact(result["alice_bits"]))
    print("  Alice bases:", _compact(result["alice_bases"]))
    if include_eve:
        print("  Eve bases:", _compact(result["eve_bases"]))
        print("  Eve bits:", _compact(result["eve_bits"]))
    print("  Bob bases:", _compact(result["bob_bases"]))
    print("  Bob bits:", _compact(result["bob_bits"]))
    print(
        "  Matching positions:",
        f"{result['matching_positions'][:32]}{'...' if len(result['matching_positions']) > 32 else ''} "
        f"(total={len(result['matching_positions'])})",
    )
    print("  Errors in sifted key:", result["errors_in_sifted_key"])
    print("  Sample QBER:", result["qber_sample_qber"])
    print("  Decision:", result["key_status"])


def main() -> None:
    normal = run_bb84_qiskit(256, seed=7, attack=False)
    attack = run_bb84_qiskit(256, seed=7, attack=True, intercept_fraction=1.0)

    _print_run("Normal BB84 result (256 qubits)", normal)
    print("  Interception flag:", normal["interception_flag"])
    _print_run("\nAttack BB84 result (256 qubits)", attack, include_eve=True)
    print("  Interception flag:", attack["interception_flag"])

    comparison = run_comparison(runs=10, n_qubits=128, base_seed=5)
    print("\nComparison summary:")
    print("  Normal mean QBER:", comparison["normal"]["mean_qber"])
    print("  Attack mean QBER:", comparison["attack"]["mean_qber"])
    print("  Detection rate:", comparison["detection_rate"])
    print("  False alarm rate:", comparison["false_alarm_rate"])

    detection = detection_rate_vs_qubits(qubit_counts=[32, 64, 128, 256], runs=6, base_seed=8)
    print("\nDetection rate by qubits:")
    print("  qubits | detection_rate | insufficient_fraction")
    for item in detection["items"]:
        rate = "None" if item["detection_rate"] is None else f"{item['detection_rate']:.3f}"
        print(
            f"  {item['qubits']:>6} | {rate:>14} | "
            f"{item['insufficient_fraction']:.3f}"
        )

    display = build_attack_display_circuit(
        attack["alice_bits"][:8],
        attack["alice_bases"][:8],
        attack["eve_bases"][:8],
        attack["bob_bases"][:8],
        max_qubits=8,
    )
    print("\nAttack display circuit (first 8 qubits):")
    print(circuit_to_text(display))


if __name__ == "__main__":
    main()
