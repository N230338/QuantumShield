from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from backend.app.main import app


@pytest.fixture(scope="module")
def client():
    """Reuse one TestClient for all endpoint checks in this module."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def bb84_runs(client):
    """Run each required BB84 mode once and share the stored API sessions."""
    normal_response = client.post(
        "/api/bb84/run",
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
    assert status.json()["pqc_status"] == "Planned – future scope"
    assert status.json()["latest_key_status"] == "REJECTED"


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
    assert received.json()["message"] == "Government meeting at 10 AM"
    assert received.json()["fingerprints_match"] is True


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
    assert len(result["step_trace"]) == 13
    assert result["key_status"] == "ACCEPTED"
    assert result["step_trace"][8]["data"]["key_status"] == "ACCEPTED"
    assert result["bb84"]["qubits_transmitted"] == 256
    assert result["sifted_length"] == result["bb84"]["sifted_length"]
    assert result["key_fingerprints"]["alice"] == result["key_fingerprints"]["bob"]
    assert result["envelope"]["ciphertext"]
    assert result["receiver"]["message"] == message
    assert "alice_final_key" not in result
    assert "revealed_keys" not in result

    history = client.get("/api/messages").json()["messages"]
    assert history[0]["message_id"] == result["message_id"]
    details = client.get(f"/api/messages/{result['message_id']}").json()
    assert details["bb84"]["sifted_length"] == result["sifted_length"]


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
