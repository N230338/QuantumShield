"""Multi-run BB84 statistics for normal vs intercept-and-resend comparison."""

from __future__ import annotations

import statistics
from typing import Any

from backend.app.bb84.core import run_bb84_qiskit


def _qber_stats(values: list[float]) -> dict[str, float]:
    if not values:
        return {"mean_qber": 0.0, "std_qber": 0.0, "min_qber": 0.0, "max_qber": 0.0}
    return {
        "mean_qber": float(statistics.fmean(values)),
        "std_qber": float(statistics.pstdev(values)) if len(values) > 1 else 0.0,
        "min_qber": float(min(values)),
        "max_qber": float(max(values)),
    }


def run_comparison(
    runs: int = 30,
    n_qubits: int = 128,
    base_seed: int | None = None,
    qber_sample_fraction: float = 0.25,
    qber_threshold: float = 0.11,
    intercept_fraction: float = 1.0,
) -> dict[str, Any]:
    """Run normal and attack-mode BB84 simulations multiple times and summarize the QBER."""
    if runs <= 0:
        raise ValueError("runs must be a positive integer.")

    normal_qbers: list[float] = []
    normal_valid_qbers: list[float] = []
    normal_sifted_lengths: list[int] = []
    normal_decisions: list[str] = []
    normal_insufficient = 0

    attack_qbers: list[float] = []
    attack_valid_qbers: list[float] = []
    attack_sifted_lengths: list[int] = []
    attack_decisions: list[str] = []
    attack_insufficient = 0

    for run_index in range(runs):
        seed = None if base_seed is None else base_seed + run_index * 101

        normal_result = run_bb84_qiskit(
            n_qubits=n_qubits,
            seed=seed,
            qber_sample_fraction=qber_sample_fraction,
            qber_threshold=qber_threshold,
            attack=False,
            intercept_fraction=intercept_fraction,
        )
        normal_qbers.append(float(normal_result["qber_sample_qber"]))
        normal_sifted_lengths.append(int(normal_result["sifted_length"]))
        normal_decisions.append(normal_result["decision"].value)
        if normal_result["decision"].value == "INSUFFICIENT_DATA":
            normal_insufficient += 1
        else:
            normal_valid_qbers.append(float(normal_result["qber_sample_qber"]))

        attack_seed = None if seed is None else seed + 1000
        attack_result = run_bb84_qiskit(
            n_qubits=n_qubits,
            seed=attack_seed,
            qber_sample_fraction=qber_sample_fraction,
            qber_threshold=qber_threshold,
            attack=True,
            intercept_fraction=intercept_fraction,
        )
        attack_qbers.append(float(attack_result["qber_sample_qber"]))
        attack_sifted_lengths.append(int(attack_result["sifted_length"]))
        attack_decisions.append(attack_result["decision"].value)
        if attack_result["decision"].value == "INSUFFICIENT_DATA":
            attack_insufficient += 1
        else:
            attack_valid_qbers.append(float(attack_result["qber_sample_qber"]))

    normal_summary = {
        "qber": normal_qbers,
        "sifted_lengths": normal_sifted_lengths,
        "decisions": normal_decisions,
        **_qber_stats(normal_valid_qbers),
        "mean_sifted_length": float(statistics.fmean(normal_sifted_lengths)) if normal_sifted_lengths else 0.0,
    }
    attack_summary = {
        "qber": attack_qbers,
        "sifted_lengths": attack_sifted_lengths,
        "decisions": attack_decisions,
        **_qber_stats(attack_valid_qbers),
        "mean_sifted_length": float(statistics.fmean(attack_sifted_lengths)) if attack_sifted_lengths else 0.0,
    }

    normal_rejected = sum(1 for decision in normal_decisions if decision == "REJECTED")
    attack_rejected = sum(1 for decision in attack_decisions if decision == "REJECTED")
    normal_valid = runs - normal_insufficient
    attack_valid = runs - attack_insufficient

    return {
        "n_qubits": n_qubits,
        "runs": runs,
        "threshold": qber_threshold,
        "normal": normal_summary,
        "attack": attack_summary,
        "detection_rate": (attack_rejected / attack_valid) if attack_valid else 0.0,
        "false_alarm_rate": (normal_rejected / normal_valid) if normal_valid else 0.0,
        "insufficient_data_runs": {"normal": normal_insufficient, "attack": attack_insufficient},
    }


def detection_rate_vs_qubits(
    qubit_counts: list[int] | None = None,
    runs: int = 30,
    base_seed: int | None = None,
    qber_sample_fraction: float = 0.25,
    qber_threshold: float = 0.11,
    intercept_fraction: float = 1.0,
) -> dict[str, Any]:
    """Return attack detection probability as a function of qubit count."""
    if qubit_counts is None:
        qubit_counts = [16, 32, 64, 128, 256]

    items: list[dict[str, Any]] = []
    for qubits in qubit_counts:
        result = run_comparison(
            runs=runs,
            n_qubits=qubits,
            base_seed=base_seed,
            qber_sample_fraction=qber_sample_fraction,
            qber_threshold=qber_threshold,
            intercept_fraction=intercept_fraction,
        )
        items.append(
            {
                "qubits": qubits,
                "detection_rate": (
                    float(result["detection_rate"])
                    if result["insufficient_data_runs"]["attack"] < runs
                    else None
                ),
                "insufficient_fraction": (
                    result["insufficient_data_runs"]["attack"] / runs
                ),
                "valid_runs": runs - result["insufficient_data_runs"]["attack"],
                "false_alarm_rate": float(result["false_alarm_rate"]),
                "attack_mean_qber": float(result["attack"]["mean_qber"]),
                "normal_mean_qber": float(result["normal"]["mean_qber"]),
            }
        )
    return {"items": items, "qubit_counts": qubit_counts, "runs": runs, "threshold": qber_threshold}
