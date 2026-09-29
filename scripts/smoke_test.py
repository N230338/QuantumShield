"""Exercise the real in-process API message pipeline and print its results."""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.main import app


SUCCESS_CASES = [
    {
        "sender": "Defence",
        "receiver": "Home Affairs",
        "message": "Route one: secure dispatch.",
        "seed": 11,
    },
    {
        "sender": "Finance",
        "receiver": "Health",
        "message": "Route two: verified records.",
        "seed": 17,
    },
    {
        "sender": "Transport",
        "receiver": "Education",
        "message": "Route three: schedule update.",
        "seed": 23,
    },
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def qber_text(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"


def main() -> None:
    rows: list[tuple[str, dict[str, object]]] = []
    successful: list[dict[str, object]] = []
    routes = {(case["sender"], case["receiver"]) for case in SUCCESS_CASES}
    require(len(routes) == 3, "Smoke test scenarios must use three distinct routes.")
    require(len({case["message"] for case in SUCCESS_CASES}) == 3, "Smoke test messages must be distinct.")

    with TestClient(app) as client:
        for case in SUCCESS_CASES:
            response = client.post(
                "/api/messages/send",
                json={**case, "n_qubits": 256, "attack": False},
            )
            require(response.status_code == 200, f"Successful route failed: {response.text}")
            result = response.json()
            require(result["key_status"] == "ACCEPTED", f"Expected accepted key, got {result['key_status']}.")
            require(result["blocked"] is False, "Accepted message was marked blocked.")
            require(result.get("envelope", {}).get("ciphertext"), "Accepted message has no ciphertext.")
            require(result.get("receiver", {}).get("message") == case["message"], "Receiver did not recover the submitted message.")
            require(result.get("key_fingerprints", {}).get("alice"), "API returned no key fingerprint.")
            successful.append(result)
            rows.append((f"{case['sender']} → {case['receiver']}", result))

        fingerprints = [item["key_fingerprints"]["alice"] for item in successful]
        require(len(set(fingerprints)) == 3, "Successful fresh sessions did not have distinct fingerprints.")

        attack_response = client.post(
            "/api/messages/send",
            json={
                "sender": "Defence",
                "receiver": "Power",
                "message": "Attack route: intercepted dispatch.",
                "n_qubits": 256,
                "attack": True,
                "intercept_fraction": 1.0,
                "noise_probability": 0.0,
                "seed": 7,
            },
        )
        require(attack_response.status_code == 200, f"Attack request failed: {attack_response.text}")
        attack_result = attack_response.json()
        require(attack_result["key_status"] == "REJECTED", f"Attack run was not rejected: {attack_result['key_status']}.")
        require(attack_result["blocked"] is True, "Rejected attack message was not blocked.")
        require("envelope" not in attack_result, "Rejected attack message unexpectedly has ciphertext.")
        require("message" not in attack_result, "Rejected attack message unexpectedly has a delivered plaintext.")
        rows.append(("Defence → Power", attack_result))

        same_route = client.post(
            "/api/messages/send",
            json={
                "sender": "Defence",
                "receiver": "Defence",
                "message": "Invalid self-route.",
                "n_qubits": 256,
            },
        )
        require(same_route.status_code == 422, f"Same-department route returned {same_route.status_code}, expected 422.")

    print("Route | Matching | QBER | Decision | Fingerprint")
    for route, result in rows:
        bb84 = result["bb84"]
        matching = f"{result['matching_count']}/{bb84['qubits_transmitted']}"
        fingerprint = result["key_fingerprints"]["alice"]
        decision = "REJECTED / BLOCKED" if result["blocked"] else result["key_status"]
        print(f"{route} | {matching} | {qber_text(result['sample_qber'])} | {decision} | {fingerprint}")
    print("Smoke test passed: 3 unique accepted sessions, 1 rejected/blocked attack, same-route 422.")


if __name__ == "__main__":
    main()