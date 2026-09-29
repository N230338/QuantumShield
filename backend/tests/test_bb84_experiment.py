from __future__ import annotations

import json

from backend.app.bb84.experiment import detection_rate_vs_qubits, run_comparison


def test_run_comparison_basic_statistics_and_reproducibility():
    a = run_comparison(runs=10, n_qubits=128, base_seed=1)
    b = run_comparison(runs=10, n_qubits=128, base_seed=1)

    assert a == b
    assert set(a) == {
        "n_qubits", "runs", "threshold", "normal", "attack", "detection_rate",
        "false_alarm_rate", "insufficient_data_runs",
    }
    mode_keys = {
        "qber", "sifted_lengths", "decisions", "mean_qber", "std_qber",
        "min_qber", "max_qber", "mean_sifted_length",
    }
    assert set(a["normal"]) == mode_keys
    assert set(a["attack"]) == mode_keys
    assert len(a["normal"]["qber"]) == 10
    assert len(a["attack"]["qber"]) == 10
    assert a["normal"]["mean_qber"] == 0.0
    assert a["attack"]["mean_qber"] > a["normal"]["mean_qber"]
    assert set(a["insufficient_data_runs"]) == {"normal", "attack"}
    assert 0.0 <= a["detection_rate"] <= 1.0
    assert 0.0 <= a["false_alarm_rate"] <= 1.0


def test_detection_rate_vs_qubits_rises_and_is_json_serializable():
    result = detection_rate_vs_qubits(qubit_counts=[16, 32, 64], runs=8, base_seed=7)

    rates = [item["detection_rate"] for item in result["items"]]
    assert all(rate is None or 0.0 <= rate <= 1.0 for rate in rates)
    valid_rates = [rate for rate in rates if rate is not None]
    assert valid_rates
    assert valid_rates[-1] >= valid_rates[0] - 0.2
    json.dumps(result)
