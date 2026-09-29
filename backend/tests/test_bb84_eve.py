from __future__ import annotations

import math
import pytest

from backend.app.bb84.core import QBERDecision, run_bb84_qiskit


def test_attack_disabled_matches_phase1_regression():
    result = run_bb84_qiskit(128, seed=7, attack=False)

    assert result["attack_enabled"] is False
    assert result["eve_bases"] in (None, [])
    assert result["eve_bits"] in (None, [])
    assert result["intercepted_mask"] in (None, [])
    assert result["decision"] == QBERDecision.ACCEPTED


@pytest.mark.slow
def test_full_attack_sifted_qber_about_25_percent():
    result = run_bb84_qiskit(512, seed=9, attack=True, intercept_fraction=1.0)

    assert 0.20 <= result["qber_full_sifted"] <= 0.30
    assert result["decision"] == QBERDecision.REJECTED
    assert result["interception_flag"] is True


@pytest.mark.slow
def test_full_attack_mean_sample_qber_about_25_percent():
    qbers = []
    for seed in (10, 11, 12, 13, 14):
        result = run_bb84_qiskit(256, seed=seed, attack=True, intercept_fraction=1.0)
        qbers.append(result["qber_sample_qber"])
    mean_qber = sum(qbers) / len(qbers)
    assert 0.19 <= mean_qber <= 0.31


@pytest.mark.slow
def test_partial_intercept_fraction_half():
    result = run_bb84_qiskit(256, seed=17, attack=True, intercept_fraction=0.5)
    assert 0.075 <= result["qber_full_sifted"] <= 0.175


def test_intercept_fraction_zero_behaves_like_no_attack():
    result = run_bb84_qiskit(128, seed=3, attack=True, intercept_fraction=0.0)

    assert result["qber_full_sifted"] == 0.0
    assert result["decision"] == QBERDecision.ACCEPTED
    assert all(not intercepted for intercepted in result["intercepted_mask"])


@pytest.mark.slow
def test_same_seed_and_settings_identical_attack_result():
    a = run_bb84_qiskit(256, seed=42, attack=True, intercept_fraction=1.0)
    b = run_bb84_qiskit(256, seed=42, attack=True, intercept_fraction=1.0)

    assert a["eve_bases"] == b["eve_bases"]
    assert a["eve_bits"] == b["eve_bits"]
    assert a["intercepted_mask"] == b["intercepted_mask"]
    assert a["bob_bits"] == b["bob_bits"]


@pytest.mark.slow
def test_eve_measurement_when_basis_matches_alice_is_deterministic():
    result = run_bb84_qiskit(128, seed=18, attack=True, intercept_fraction=1.0)

    for idx in range(len(result["alice_bits"])):
        if result["eve_bases"][idx] == result["alice_bases"][idx]:
            assert result["eve_bits"][idx] == result["alice_bits"][idx]


@pytest.mark.slow
def test_rejected_on_full_attack_and_accepted_without_attack():
    attack_result = run_bb84_qiskit(256, seed=21, attack=True, intercept_fraction=1.0)
    normal_result = run_bb84_qiskit(256, seed=21, attack=False)

    assert attack_result["decision"] == QBERDecision.REJECTED
    assert attack_result["key_status"] == "REJECTED"
    assert attack_result["interception_flag"] is True
    assert normal_result["decision"] == QBERDecision.ACCEPTED
    assert normal_result["key_status"] == "ACCEPTED"
    assert normal_result["interception_flag"] is False


def test_insufficient_data_is_not_flagged_as_interception():
    result = run_bb84_qiskit(8, seed=5, attack=True)

    assert result["decision"] == QBERDecision.INSUFFICIENT_DATA
    assert result["key_status"] == "INSUFFICIENT_DATA"
    assert result["interception_flag"] is False


@pytest.mark.slow
def test_errors_in_sifted_key_count_only_when_eve_basis_differs():
    result = run_bb84_qiskit(256, seed=33, attack=True, intercept_fraction=1.0)

    for idx in result["matching_positions"]:
        if result["eve_bases"][idx] == result["alice_bases"][idx]:
            assert result["eve_bits"][idx] == result["alice_bits"][idx]

    assert result["errors_in_sifted_key"] >= 0


def test_validation_for_intercept_fraction():
    try:
        run_bb84_qiskit(128, seed=5, attack=True, intercept_fraction=-0.1)
        raise AssertionError("Expected ValueError")
    except ValueError:
        pass

    try:
        run_bb84_qiskit(128, seed=5, attack=True, intercept_fraction=1.5)
        raise AssertionError("Expected ValueError")
    except ValueError:
        pass
