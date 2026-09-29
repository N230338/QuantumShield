"""Demonstrate BB84 key establishment and separate AES-GCM message protection."""

from __future__ import annotations

import base64
import json
import sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from backend.app.bb84.core import run_bb84_qiskit
from backend.app.messaging.secure_channel import (
    KeyNotAcceptedError,
    key_fingerprint,
    receive_secure_message,
    send_secure_message,
)
from backend.app.pqc.interface import get_pqc_status

MESSAGE = "Government meeting at 10 AM"


def main() -> None:
    print("KEY ESTABLISHMENT FLOW")
    normal = run_bb84_qiskit(256, seed=7)
    print("  QBER:", normal["qber_sample_qber"])
    print("  Decision:", normal["key_status"])
    print("  Final key length:", len(normal["alice_final_key"]))
    print("  Alice key fingerprint:", key_fingerprint(normal["alice_final_key"]))
    print("  Bob key fingerprint:", key_fingerprint(normal["bob_final_key"]))

    print("\nACTUAL MESSAGE FLOW")
    print("  Actual message:", MESSAGE)
    envelope = send_secure_message(normal, MESSAGE)
    encoded = envelope.to_dict()
    print("  Ciphertext (base64):", encoded["ciphertext"])
    print("  Envelope (JSON):", json.dumps(encoded))
    print("  Receiver recovered:", receive_secure_message(normal, envelope))

    attacked = run_bb84_qiskit(256, seed=7, attack=True)
    print("\nAttack result:", attacked["key_status"])
    try:
        send_secure_message(attacked, MESSAGE)
    except KeyNotAcceptedError as exc:
        print("  Sending blocked:", exc)

    print("\nPQC PLACEHOLDER")
    print(json.dumps(get_pqc_status(), ensure_ascii=False))


if __name__ == "__main__":
    main()
