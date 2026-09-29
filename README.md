# QuantumShield

QuantumShield is a simulation prototype demonstrating BB84 quantum key distribution, an intercept-and-resend attacker, and protection of actual messages using HKDF-SHA256 and AES-256-GCM. It uses Qiskit Aer simulation; it is not a physical quantum network.

Our current prototype demonstrates the QKD/BB84 component through simulation, while the overall architecture proposes integration with PQC.

## Implemented and Future Scope

| Component | Status |
| --- | --- |
| BB84 key establishment and QBER checks | Implemented in simulation |
| Eve intercept-and-resend simulation | Implemented in simulation |
| Actual-message protection with AES-GCM | Implemented |
| Post-quantum cryptography (PQC) | Planned – future scope; placeholder only |
| Physical quantum network | Not implemented |

BB84 establishes key material; it does not encrypt the actual message. PQC is classical cryptography designed to resist quantum attacks and is different from, but complementary to, QKD.

## How to Run

On Windows, from the project root, start the dashboard with:

```powershell
.\run_dashboard.ps1
```

The script activates `.venv` and runs Uvicorn. Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The app serves the static dashboard and API from the same process. Direct invocation is also available:

```powershell
.\.venv\Scripts\python -m uvicorn backend.app.main:app --port 8000
```

Install dependencies into the virtual environment with:

```powershell
.\.venv\Scripts\python -m pip install -r backend\requirements.txt
```

Run the non-slow backend tests with:

```powershell
.\.venv\Scripts\python -m pytest backend\tests -m "not slow" -q
```

## Simulation Limits

No physical photons, fibre, or real quantum network are used. A high QBER can be consistent with possible interception, but channel noise or faults can also raise it. A production QKD system would additionally require error correction, privacy amplification, and an authenticated classical channel. The message layer demonstrates standard cryptography using an established key; it does not make the system unbreakable or absolutely secure.
