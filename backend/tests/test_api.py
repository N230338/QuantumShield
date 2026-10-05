from __future__ import annotations

import time
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app, state
from backend.app.pqc.interface import PQCError


@pytest.fixture(scope="module")
def client():
    """Reuse one TestClient for all endpoint checks in this module."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def bb84_runs(client):
    """Run each required BB84 mode once and share the stored API sessions."""
    normal_response = client.post(
        "/api/bb84/run?reveal_key=true",
        json={"n_qubits": 256, "seed": 7, "attack": False},
    )
    attack_response = client.post(
        "/api/bb84/run",
        json={"n_qubits": 256, "seed": 7, "attack": True},
    )
    assert normal_response.status_code == 200
    assert attack_response.status_code == 200
    return normal_response.json(), attack_response.json()


def test_health_and_status(client, bb84_runs):
    health = client.get("/api/health")
    status = client.get("/api/status")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert status.status_code == 200
    assert status.json()["pqc_status"] == "ML-KEM-768 IMPLEMENTED"
    assert status.json()["latest_key_status"] == "REJECTED"
    assert status.json()["communication_status"] == "KEY_UNAVAILABLE"

    accepted = client.post("/api/bb84/run", json={"n_qubits": 256, "seed": 7})
    assert accepted.status_code == 200
    assert client.get("/api/status").json()["communication_status"] == "KEY_AVAILABLE"


def test_normal_run_is_accepted_and_does_not_expose_raw_key(bb84_runs):
    normal, _ = bb84_runs

    assert normal["key_status"] == "ACCEPTED"
    assert normal["interception_flag"] is False
    assert normal["sample_qber"] == 0.0
    assert len(normal["arrays"]["alice_bits"]["values"]) == 64
    assert "revealed_keys" not in normal
    assert normal["key_fingerprints"]["alice"] == normal["key_fingerprints"]["bob"]


def test_attack_run_is_rejected_and_flagged(bb84_runs):
    _, attack = bb84_runs

    assert attack["key_status"] == "REJECTED"
    assert attack["interception_flag"] is True
    assert "eve_bits" in attack["arrays"]
    assert attack["sample_qber"] > 0.11


@pytest.mark.slow
@pytest.mark.parametrize("mode", ["normal", "attack"])
def test_circuit_endpoint_generates_runtime_circuit(client, bb84_runs, mode):
    normal, attack = bb84_runs
    response_data = normal if mode == "normal" else attack
    response = client.get(f"/api/bb84/{response_data['session_id']}/circuit")

    assert response.status_code == 200
    circuits = response.json()
    assert circuits["normal"]["text"].strip()
    assert circuits["normal"]["png_base64"]
    if mode == "attack":
        assert circuits["attack"]["text"].strip()
        assert circuits["attack"]["png_base64"]


def test_message_send_and_receive_round_trip(client, bb84_runs):
    normal, _ = bb84_runs
    sent = client.post(
        "/api/message/send",
        json={"session_id": normal["session_id"], "message": "Government meeting at 10 AM"},
    )

    assert sent.status_code == 200
    assert sent.json()["encrypted_message"]["ciphertext"]
    assert "Government meeting" not in sent.json()["encrypted_message"]["ciphertext"]

    received = client.post(
        "/api/message/receive",
        json={"session_id": normal["session_id"]},
    )
    assert received.status_code == 200
    assert received.json()["authenticated"] is True
    assert received.json()["message_length"] == len("Government meeting at 10 AM")
    assert received.json()["message"] == "Government meeting at 10 AM"
    assert received.json()["fingerprints_match"] is True


@pytest.mark.parametrize(
    "message",
    [
        "x",
        "a" * 100,
        "b" * 1000,
        "c" * 10000,
        "  First line\nSecond line\r\n  Third line  ",
    ],
)
def test_authenticated_receive_returns_complete_message(client, message):
    sent = client.post(
        "/api/messages/send",
        json={
            "sender": "Defence",
            "receiver": "Home Affairs",
            "message": message,
            "n_qubits": 256,
            "security_mode": "hybrid",
            "seed": 7,
        },
    )

    assert sent.status_code == 200
    assert "message" not in sent.json()

    received = client.post(
        "/api/message/receive",
        json={"session_id": sent.json()["session_id"]},
    )
    assert received.status_code == 200
    assert received.json()["authenticated"] is True
    assert received.json()["message"] == message
    assert received.json()["message_length"] == len(message)


def test_message_pipeline_returns_real_trace_without_raw_key_material(client):
    message = "Pipeline contract test"
    response = client.post(
        "/api/messages/send",
        json={
            "sender": "Defence",
            "receiver": "Home Affairs",
            "message": message,
            "n_qubits": 256,
            "attack": False,
            "seed": 7,
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert len(result["step_trace"]) == 16
    assert result["key_status"] == "ACCEPTED"
    assert result["step_trace"][8]["data"]["key_status"] == "ACCEPTED"
    assert result["bb84"]["qubits_transmitted"] == 256
    assert result["sifted_length"] == result["bb84"]["sifted_length"]
    assert result["key_fingerprints"]["alice"] == result["key_fingerprints"]["bob"]
    assert result["envelope"]["ciphertext"]
    assert result["security_mode"] == "hybrid"
    assert result["security_status"]["mlkem"] == "ESTABLISHED"
    assert result["security_status"]["hybrid_derivation"] == "DERIVED"
    assert result["security_status"]["aes_gcm"] == "AUTHENTICATED"
    assert result["security_status"]["tampering_detection"] == "DETECTED"
    assert result["receiver"]["authenticated"] is True
    assert "message" not in result["receiver"]
    assert "Pipeline contract test" not in str(result)
    assert "alice_final_key" not in result
    assert "revealed_keys" not in result

    history = client.get("/api/messages").json()["messages"]
    assert history[0]["message_id"] == result["message_id"]
    assert message not in str(history)
    details = client.get(f"/api/messages/{result['message_id']}").json()
    assert details["bb84"]["sifted_length"] == result["sifted_length"]
    assert message not in str(details)

    received = client.post(
        "/api/message/receive",
        json={"session_id": result["session_id"]},
    )
    assert received.status_code == 200
    assert received.json()["authenticated"] is True
    history_after_receive = client.get("/api/messages").json()["messages"]
    assert history_after_receive[0]["decrypted_message"] == message
    assert history_after_receive[0]["timings_seconds"]["receiver_decryption"] >= 0
    details_after_receive = client.get(f"/api/messages/{result['message_id']}").json()
    assert details_after_receive["decrypted_message"] == message
    assert details_after_receive["timings_seconds"]["receiver_decryption"] >= 0


def test_rejected_message_pipeline_does_not_encrypt_or_deliver(client):
    response = client.post(
        "/api/messages/send",
        json={
            "sender": "Defence",
            "receiver": "Home Affairs",
            "message": "This should be withheld",
            "n_qubits": 256,
            "attack": True,
            "seed": 7,
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["key_status"] == "REJECTED"
    assert result["blocked"] is True
    assert result["withheld"] is True
    assert result["step_trace"][8]["status"] == "blocked"
    assert all(step["status"] == "blocked" for step in result["step_trace"][9:])
    assert "envelope" not in result
    assert result["receiver"] == "Home Affairs"
    assert "message" not in result
    blocked_history = client.get("/api/messages").json()["messages"]
    assert blocked_history[0]["message_id"] == result["message_id"]
    assert "decrypted_message" not in blocked_history[0]


def test_mlkem_mode_can_proceed_when_qber_rejects_qkd_material(client):
    response = client.post(
        "/api/messages/send",
        json={
            "sender": "Defence",
            "receiver": "Home Affairs",
            "message": "ML-KEM does not consume rejected QKD material",
            "security_mode": "ml-kem",
            "n_qubits": 256,
            "attack": True,
            "seed": 7,
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["key_status"] == "REJECTED"
    assert result["blocked"] is False
    assert result["security_status"]["bb84"] == "REJECTED"
    assert result["security_status"]["mlkem"] == "ESTABLISHED"
    assert result["security_status"]["aes_gcm"] == "AUTHENTICATED"
    assert result["envelope"]["security_mode"] == "ml-kem"
    assert "mlkem_receiver_secret" not in result
    received = client.post(
        "/api/message/receive",
        json={"session_id": result["session_id"]},
    )
    assert received.status_code == 200
    assert received.json()["authenticated"] is True
    assert received.json()["message_length"] == len("ML-KEM does not consume rejected QKD material")
    assert received.json()["message"] == "ML-KEM does not consume rejected QKD material"


def test_hybrid_mode_establishes_both_components_and_authenticates(client):
    response = client.post(
        "/api/messages/send",
        json={
            "sender": "Defence",
            "receiver": "Home Affairs",
            "message": "Hybrid API integration",
            "security_mode": "hybrid",
            "n_qubits": 256,
            "seed": 7,
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["blocked"] is False
    assert result["security_status"]["bb84"] == "ACCEPTED"
    assert result["security_status"]["mlkem"] == "ESTABLISHED"
    assert result["security_status"]["hybrid_derivation"] == "DERIVED"
    assert result["security_status"]["aes_gcm"] == "AUTHENTICATED"
    assert result["security_status"]["tampering_detection"] == "DETECTED"


def test_hybrid_mode_blocks_rejected_qber_without_key_fallback(client):
    response = client.post(
        "/api/messages/send",
        json={
            "sender": "Defence",
            "receiver": "Home Affairs",
            "message": "Hybrid must not fall back",
            "security_mode": "hybrid",
            "n_qubits": 256,
            "attack": True,
            "seed": 7,
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["blocked"] is True
    assert result["key_status"] == "REJECTED"
    assert result["security_status"]["mlkem"] == "NOT_PERFORMED"
    assert result["security_status"]["hybrid_derivation"] == "NOT_PERFORMED"
    assert "envelope" not in result


def test_hybrid_mode_fails_closed_when_mlkem_establishment_fails(client, monkeypatch):
    def fail_establishment(_self):
        raise PQCError("sensitive internal details")

    monkeypatch.setattr(
        "backend.app.main.MLKEM768Provider.establish_shared_secret",
        fail_establishment,
    )
    response = client.post(
        "/api/messages/send",
        json={
            "sender": "Defence",
            "receiver": "Home Affairs",
            "message": "No downgrade",
            "security_mode": "hybrid",
            "n_qubits": 256,
            "seed": 7,
        },
    )

    assert response.status_code == 503
    assert "no fallback was used" in response.json()["detail"]
    assert "sensitive internal details" not in response.text


@pytest.mark.parametrize("tamper_field", ["ciphertext", "aad"])
def test_receive_endpoint_withholds_plaintext_after_tampering(client, tamper_field):
    message = "Authenticated content must stay private after tampering."
    sent = client.post(
        "/api/messages/send",
        json={
            "sender": "Defence",
            "receiver": "Home Affairs",
            "message": message,
            "security_mode": "hybrid",
            "n_qubits": 256,
            "seed": 7,
        },
    )
    assert sent.status_code == 200
    session = state.get_session(sent.json()["session_id"])
    assert session is not None
    assert session.encrypted_message is not None

    envelope = session.encrypted_message
    if tamper_field == "ciphertext":
        changed_ciphertext = bytearray(envelope.ciphertext)
        changed_ciphertext[0] ^= 1
        session.encrypted_message = replace(envelope, ciphertext=bytes(changed_ciphertext))
    else:
        changed_aad = bytearray(envelope.aad)
        changed_aad[0] ^= 1
        session.encrypted_message = replace(envelope, aad=bytes(changed_aad))

    received = client.post(
        "/api/message/receive",
        json={"session_id": session.session_id},
    )

    assert received.status_code == 409
    assert "authentication or decryption failed" in received.json()["detail"]
    assert "message" not in received.json()
    assert message not in received.text


def test_message_pipeline_rejects_unknown_security_mode(client):
    response = client.post(
        "/api/messages/send",
        json={
            "sender": "Defence",
            "receiver": "Home Affairs",
            "message": "Invalid mode",
            "security_mode": "legacy-kyber",
        },
    )

    assert response.status_code == 422


def test_message_send_is_blocked_after_attack(client, bb84_runs):
    _, attack = bb84_runs
    response = client.post(
        "/api/message/send",
        json={"session_id": attack["session_id"], "message": "Blocked message"},
    )

    assert response.status_code == 409
    assert "ACCEPTED key is required" in response.json()["detail"]


def test_unknown_session_and_invalid_qubit_count_return_http_errors(client):
    unknown = client.post(
        "/api/message/receive",
        json={"session_id": "not-a-session"},
    )
    invalid = client.post("/api/bb84/run", json={"n_qubits": 7})

    assert unknown.status_code == 404
    assert "session was not found" in unknown.json()["detail"]
    assert invalid.status_code == 422


@pytest.mark.slow
def test_background_comparison_job_completes_and_is_cached(client):
    started = client.post(
        "/api/experiments/compare",
        json={"runs": 1, "n_qubits": 256, "base_seed": 19},
    )
    assert started.status_code == 202
    job_id = started.json()["job_id"]
    job = None
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        job_response = client.get(f"/api/experiments/{job_id}")
        assert job_response.status_code == 200
        job = job_response.json()
        if job["status"] != "running":
            break
        time.sleep(0.05)

    assert job is not None
    assert job["status"] == "done"
    assert job["progress"] == 1.0
    assert job["result"]["n_qubits"] == 256
    assert client.get("/api/experiments/last").json()["result"] == job["result"]


def test_unknown_experiment_job_returns_404(client):
    assert client.get("/api/experiments/no-such-job").status_code == 404
