# QuantumShield

QuantumShield is a local communication-security demonstration. It combines a **BB84 software simulation**, standardized **ML-KEM-768 (NIST FIPS 203)** key establishment, an explicitly domain-separated hybrid KDF, and **AES-256-GCM** message encryption and authentication. It is not a physical quantum network and has not received a production security review.

Key establishment and message encryption are separate operations: BB84 and/or ML-KEM establish secret material; HKDF-SHA256 derives an AES key; AES-GCM encrypts, authenticates, and protects the actual message.

## Key-establishment paths

| Path | Key-establishment inputs | QBER behavior |
| --- | --- | --- |
| **BB84 + AES-GCM** | Accepted BB84-derived material | Refuses encryption unless BB84 accepts QBER and at least 64 final key bits remain |
| **ML-KEM + AES-GCM** | Fresh ML-KEM-768 encapsulated secret | Reports the BB84 simulation/QBER, but never consumes BB84 key material |
| **Hybrid BB84 + ML-KEM + AES-GCM** | Both accepted BB84 material and a fresh ML-KEM-768 secret | Fails closed if BB84 rejects QBER, the key is too short, or ML-KEM fails; there is no downgrade |

ML-KEM uses the maintained `pqcrypto` Rust bindings and its FIPS 203 `pqcrypto.kem.ml_kem_768` API. It does not use pre-standard Kyber. Public/private key pairs and shared secrets are ephemeral to each message and are not returned to the dashboard or written to message history.

### Hybrid KDF construction

For every message, the sender and receiver independently derive the same 256-bit AES key with HKDF-SHA256 and a fresh 16-byte salt. In hybrid mode the HKDF input key material is:

```text
"QuantumShield hybrid IKM v1\0"
|| uint32_be(length(BB84_bytes)) || BB84_bytes
|| uint32_be(length(ML-KEM_secret)) || ML-KEM_secret
```

The HKDF `info` contains the `QuantumShield AES-256-GCM key v1` protocol label, the selected mode, and the route-bound AES-GCM AAD. Length-prefixing avoids ambiguous input concatenation; mode and route domain separation prevent keys from being reused across modes or recipient routes. A fresh random 12-byte GCM nonce is generated per encryption. Modified ciphertext is checked against AES-GCM authentication and rejected.

This construction is a prototype design, not a claim of formal security for an arbitrary hybrid combiner.
The dashboard always uses the hybrid path; alternate paths remain available to API/library callers.

## Architecture

```text
Browser dashboard
  └─ FastAPI message pipeline
       ├─ BB84 / Qiskit Aer simulation → sampled QBER decision
       ├─ ML-KEM-768 → encapsulated shared secret
       ├─ hybrid HKDF-SHA256 (accepted BB84 + ML-KEM) → AES-256 key
       └─ AES-256-GCM → ciphertext + nonce + salt + authenticated route
```

- `backend/app/bb84/`: BB84 logic, QBER evaluation, and Qiskit/Aer simulation.
- `backend/app/pqc/interface.py`: ML-KEM-768 provider contract and sender/receiver agreement check.
- `backend/app/messaging/secure_channel.py`: HKDF, AES-GCM envelope, and authenticated decryption.
- `backend/app/main.py`: API endpoints and the integrated per-message pipeline.
- `frontend/`: hybrid message composer, simulation controls, and read-only security status display.

## Install and run

Python 3.10+ is required. From the project root on Windows:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The manifests include FastAPI/Uvicorn, Qiskit/Aer, `cryptography` for HKDF/AES-GCM, and `pqcrypto>=1.0.0` for standardized ML-KEM-768. To install only the PQC dependency into an existing environment:

```powershell
python -m pip install "pqcrypto>=1.0.0"
```

Start the existing dashboard:

```powershell
.\run_dashboard.ps1
```

Then open [http://127.0.0.1:8000](http://127.0.0.1:8000). The API and static frontend are served by the same process. Direct invocation is also supported:

```powershell
.\.venv\Scripts\python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

## Usage

1. Open the dashboard and enter a message. The dashboard uses the hybrid BB84 + ML-KEM-768 + AES-GCM path.
2. Optionally adjust the BB84 QBER threshold in **Advanced**.
3. Click **Encrypt & Send Securely**. The read-only security panel reports the BB84/QBER result, ML-KEM status, hybrid derivation status, AES-GCM status, and ciphertext-tampering check.
4. A rejected or insufficient QBER result blocks hybrid message delivery; ML-KEM failure also fails closed without a downgrade.
5. Click **Decrypt Message** in the receiver panel. The complete plaintext is displayed only after AES-GCM authentication succeeds; long output wraps and can be scrolled.

Message text, including whitespace and line breaks, is preserved. Message history stores metadata and a generic length-only preview, not plaintext, private keys, or shared secrets. The send response does not include plaintext; the receive response includes it only after authenticated decryption.

The main route-aware endpoint is `POST /api/messages/send`. Its request includes `sender`, `receiver`, `message`, and optional `security_mode` (`bb84`, `ml-kem`, or `hybrid`, defaulting to `hybrid`); BB84 options include `n_qubits`, `attack`, `noise_probability`, `qber_sample_fraction`, `qber_threshold`, and `seed`. On success, the response includes safe stage/status metadata and an encrypted envelope, never the derived key or plaintext. `POST /api/message/receive` returns plaintext only after authenticated decryption succeeds.

## Repeatable live demonstration

Run the dashboard locally and use the default 256 qubits. For repeatable simulation outcomes, open **Advanced** and enter seed `7`. The seed controls this simulated run only; leave it blank when you want fresh randomness. No step uses physical quantum hardware.

1. **Normal secure communication:** Ensure **Simulate interception (Eve)** is unchecked. Enter a sample message, choose different sender and receiver departments, set seed `7`, and click **Encrypt & Send Securely**. With these fixture settings, BB84 is accepted. Follow the five dashboard stages: BB84/QBER, ML-KEM-768, hybrid derivation, AES-GCM, and receiver verification. The live panel reports returned outcomes; a blocked or failed stage is not reported as a success.
2. **Successful reception:** Click **Decrypt Message**. The receiver API verifies the stored envelope with AES-GCM and returns plaintext only after tag verification. The complete original text then appears in the receiver panel. For a display test, repeat with Unicode or multiline text; long output wraps and scrolls.
3. **Eavesdropping simulation:** Enter a new message, keep 256 qubits and seed `7`, and check **Simulate interception (Eve)** before sending. The deterministic intercept-and-resend fixture raises sampled QBER above the default 11% threshold. The dashboard reports the returned QBER and rejection decision; hybrid establishment and encryption do not proceed, and decryption is disabled. QBER indicates errors in this model, not proof of a real attacker.
4. **Tampering detection:** Send a normal accepted message. During that send, the backend makes a separate test copy of the encrypted envelope, flips one ciphertext bit, and attempts receiver authentication. The live **Tampering check** reports `DETECTED` only when AES-GCM rejects the modified envelope. This probe does not alter the valid stored message, which can still be received. Automated API tests also mutate ciphertext and authenticated data and verify that receive returns an error without plaintext.
5. **Failure handling:** A rejected QBER result is demonstrated in step 3. The automated suite injects ML-KEM establishment failure and verifies a no-fallback response; invalid ciphertext/authentication data also fails closed. These failures do not expose key material or present a failed operation as successful.

For a projector, use a desktop browser at a wide window size; the workflow rail and receiver message layout reflow on narrow screens. Stage labels describe API-returned outcomes, and receiver plaintext remains hidden until a successful receive response arrives.

## Testing

Run the complete backend test suite:

```powershell
.\.venv\Scripts\python -m pytest backend\tests -q
```

Run the fast tests without marked simulation-heavy cases:

```powershell
.\.venv\Scripts\python -m pytest backend\tests -m "not slow" -q
```

Coverage includes ML-KEM shared-secret agreement and input validation, mode-separated derivation, AES-GCM round trips and tamper rejection, QBER-based key refusal, hybrid failure/no-downgrade behavior, and existing BB84/API functionality.

## Limitations

- BB84 and quantum circuits run in software with Qiskit Aer; there are no photons, quantum devices, or physical QKD links.
- Simulated QBER does not prove interception. Real QKD needs authenticated classical communication, error correction, privacy amplification, and a carefully engineered physical channel.
- This in-process demonstration generates both sides of ML-KEM key establishment. A network deployment still needs authenticated recipient public-key distribution, protocol/session design, replay defenses, key lifecycle management, and secure storage/transport.
- The in-memory application state is not durable or designed for multi-worker deployment.
- The KDF composition, library integration, and application have not had a formal security audit. Do not treat this as production-grade security or as a substitute for a reviewed protocol.
- `pqcrypto` wraps Rust implementations, but the dependency's use in this application has not been independently audited.
