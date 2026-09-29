from __future__ import annotations

from backend.app.bb84.core import (
    QBERDecision,
    generate_bases,
    generate_bits,
    run_bb84,
    sift_positions,
)


def test_reproducible_seed_generators():
    bits_a = generate_bits(64, seed=123)
    bases_a = generate_bases(64, seed=123)
    bits_b = generate_bits(64, seed=123)
    bases_b = generate_bases(64, seed=123)

    assert bits_a == bits_b
    assert bases_a == bases_b


def test_same_basis_same_bit_without_noise():
    result = run_bb84(128, seed=7, qber_sample_fraction=0.25)

    assert result["qber"] == 0.0
    assert result["decision"] == QBERDecision.ACCEPTED
    assert result["sifted_length"] == len(result["sifted_positions"])
    assert len(result["sifted_key"]) == result["final_key_length"]


def test_sifting_matches_basis_agreement():
    result = run_bb84(64, seed=11)

    matching = result["matching_positions"]
    sifted = result["sifted_positions"]

    assert len(sifted) == len(matching)
    for idx in matching:
        assert result["alice_bases"][idx] == result["bob_bases"][idx]
    for idx in range(len(result["alice_bases"])):
        if idx not in matching:
            assert result["alice_bases"][idx] != result["bob_bases"][idx]


def test_insufficient_data_returns_status():
    result = run_bb84(8, seed=3, qber_sample_fraction=0.5)

    assert result["decision"] == QBERDecision.INSUFFICIENT_DATA
    assert "insufficient" in result["reason"].lower()


def test_accept_reject_threshold_logic():
    accept = run_bb84(256, seed=99, qber_threshold=0.11)
    reject = run_bb84(256, seed=99, attack=True, intercept_fraction=1.0, qber_threshold=0.01)

    assert accept["decision"] == QBERDecision.ACCEPTED
    assert reject["decision"] == QBERDecision.REJECTED


def test_run_bb84_returns_expected_keys_and_lengths():
    result = run_bb84(80, seed=23)

    assert len(result["alice_bits"]) == 80
    assert len(result["bob_bits"]) == 80
    assert len(result["alice_bases"]) == 80
    assert len(result["bob_bases"]) == 80
    assert len(result["sifted_key"]) == result["final_key_length"]
    assert result["decision"] in {
        QBERDecision.ACCEPTED,
        QBERDecision.REJECTED,
        QBERDecision.INSUFFICIENT_DATA,
    }
