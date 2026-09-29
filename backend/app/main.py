"""FastAPI backend and static dashboard host for the QuantumShield simulation."""

from __future__ import annotations

import os
import threading
import time
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.app.bb84.circuits import (
    build_attack_display_circuit,
    build_display_circuit,
    circuit_to_png_base64,
    circuit_to_text,
)
from backend.app.bb84.core import run_bb84_qiskit
from backend.app.bb84.experiment import detection_rate_vs_qubits, run_comparison
from backend.app.messaging.secure_channel import (
    DecryptionError,
    KeyNotAcceptedError,
    KeyTooShortError,
    key_fingerprint,
    receive_secure_message,
    send_secure_message,
)
from backend.app.pqc.interface import get_pqc_status
from backend.app.schemas import (
    BB84RunRequest,
    ComparisonRequest,
    DetectionVsQubitsRequest,
    MessagePipelineRequest,
    MessageReceiveRequest,
    MessageSendRequest,
)
from backend.app.state import JobRecord, MessageRecord, SessionRecord, state


app = FastAPI(
    title="QuantumShield Simulation Dashboard API",
    description=(
        "Simulation-only BB84 key establishment and actual-message encryption. "
        "PQC remains planned future scope."
    ),
    version="0.1.0",
)

_ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:5500",
    "http://127.0.0.1:5500",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
_EXTRA_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "").split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS + _EXTRA_ORIGINS,
    allow_origin_regex=r"https?://.*\.onrender\.com",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DISPLAY_POSITIONS = 64
CIRCUIT_POSITIONS = 8
SAME_DEPARTMENT_ERROR = "Sender and receiver must be different departments. Please select different departments."
DEPARTMENTS = [
    {"id": "defence", "name": "Defence"},
    {"id": "home-affairs", "name": "Home Affairs"},
    {"id": "finance", "name": "Finance"},
    {"id": "health", "name": "Health"},
    {"id": "electronics", "name": "Electronics"},
    {"id": "education", "name": "Education"},
    {"id": "railways", "name": "Railways"},
    {"id": "power", "name": "Power"},
    {"id": "transport", "name": "Transport"},
    {"id": "agriculture", "name": "Agriculture"},
    {"id": "environment", "name": "Environment"},
]
_DEPARTMENT_BY_ID = {item["id"]: item for item in DEPARTMENTS}
_DEPARTMENT_BY_NAME = {item["name"].casefold(): item for item in DEPARTMENTS}


def _compact(values: list[Any], length: int) -> str:
    """Render bit/basis/status sequences without exposing anything beyond length."""
    return "".join("?" if value is None else str(value) for value in values[:length])


def _array_summary(values: list[Any]) -> dict[str, Any]:
    """Return a compact sequence, its display prefix, and original total length."""
    return {
        "compact": _compact(values, DISPLAY_POSITIONS),
        "values": values[:DISPLAY_POSITIONS],
        "total": len(values),
    }


def _plain_result(result: Any) -> dict[str, Any]:
    """Convert BB84Result explicitly to a plain dict suitable for API processing."""
    data = asdict(result)
    decision = data.get("decision")
    data["decision"] = getattr(decision, "value", decision)
    return data


def _response_for_run(
    session: SessionRecord,
    elapsed_seconds: float,
    reveal_key: bool,
) -> dict[str, Any]:
    """Build the default key-safe run response from a plain serialized BB84 result."""
    result = session.result
    arrays = {
        "alice_bits": _array_summary(result["alice_bits"]),
        "alice_bases": _array_summary(result["alice_bases"]),
        "bob_bases": _array_summary(result["bob_bases"]),
        "bob_bits": _array_summary(result["bob_bits"]),
        "matching_mask": _array_summary(result["matching_mask"]),
    }
    if result["attack_enabled"]:
        arrays.update(
            {
                "eve_bases": _array_summary(result["eve_bases"] or []),
                "eve_bits": _array_summary(result["eve_bits"] or []),
                "intercepted_mask": _array_summary(result["intercepted_mask"] or []),
            }
        )

    positions = result["matching_positions"]
    response: dict[str, Any] = {
        "session_id": session.session_id,
        "arrays": arrays,
        "matching_positions": positions[:DISPLAY_POSITIONS],
        "matching_positions_count": len(positions),
        "qubits_transmitted": len(result["alice_bits"]),
        "sifted_length": result["sifted_length"],
        "sample_size": result["sample_size"],
        "final_key_length": result["final_key_length"],
        "sample_qber": result["qber_sample_qber"],
        "full_sifted_qber_analysis_only": result["qber_full_sifted"],
        "key_status": result["key_status"],
        "interception_flag": result["interception_flag"],
        "attack_enabled": result["attack_enabled"],
        "intercept_fraction": result["intercept_fraction"],
        "reason": result["reason"],
        "elapsed_seconds": elapsed_seconds,
        "key_fingerprints": {
            "alice": key_fingerprint(result["alice_final_key"]),
            "bob": key_fingerprint(result["bob_final_key"]),
        },
    }
    if reveal_key and result["key_status"] == "ACCEPTED":
        response["revealed_keys"] = {
            "alice": result["alice_final_key"],
            "bob": result["bob_final_key"],
        }
    return response


def _require_session(session_id: str) -> SessionRecord:
    """Return a session or raise a client-safe 404."""
    record = state.get_session(session_id)
    if record is None:
        raise HTTPException(status_code=404, detail="BB84 session was not found.")
    return record


def _canonical_department(value: str) -> dict[str, str]:
    """Resolve a department ID or exact display name to its canonical entry."""
    department = _DEPARTMENT_BY_ID.get(value) or _DEPARTMENT_BY_NAME.get(value.casefold())
    if department is None:
        raise HTTPException(status_code=422, detail=SAME_DEPARTMENT_ERROR)
    return department


def _validate_route(sender_value: str, receiver_value: str) -> tuple[dict[str, str], dict[str, str]]:
    """Resolve and validate two distinct sender/receiver departments."""
    sender = _canonical_department(sender_value)
    receiver = _canonical_department(receiver_value)
    if sender["id"] == receiver["id"]:
        raise HTTPException(status_code=422, detail=SAME_DEPARTMENT_ERROR)
    return sender, receiver


def _step(
    number: int,
    title: str,
    what: str,
    why: str,
    status: str,
    data: Any = None,
    elapsed_seconds: float | None = None,
) -> dict[str, Any]:
    """Build one serializable message-pipeline step."""
    return {
        "number": number,
        "title": title,
        "what_happens": what,
        "why_it_matters": why,
        "status": status,
        "data": data,
        "elapsed_seconds": elapsed_seconds,
    }


def _launch_job(
    operation: Callable[[], dict[str, Any]],
    *,
    cache_result: str | None = None,
) -> JobRecord:
    """Start a daemon worker and return its job record immediately."""
    job = state.create_job()

    def worker() -> None:
        current = state.get_job(job.job_id)
        if current is not None:
            state.update_job_progress(job.job_id, 0.05)
        try:
            result = operation()
            state.complete_job(job.job_id, result, cache=cache_result)
        except Exception as exc:  # Errors are stored as short client-safe text, never tracebacks.
            state.fail_job(job.job_id, f"Experiment failed: {exc}")

    threading.Thread(target=worker, name=f"experiment-{job.job_id[:8]}", daemon=True).start()
    return job


@app.get("/api/health")
def health() -> dict[str, str]:
    """Return basic process health."""
    return {"status": "ok"}


@app.get("/api/departments")
def get_departments() -> list[dict[str, str]]:
    """Return the approved sender and receiver department choices."""
    return [item.copy() for item in DEPARTMENTS]


@app.get("/api/status")
def dashboard_status() -> dict[str, Any]:
    """Return QKD, PQC, communication, and latest interception status."""
    latest = state.get_session(state.latest_session_id) if state.latest_session_id else None
    interception = latest.result["interception_flag"] if latest else None
    latest_key_status = latest.result["key_status"] if latest else "NOT_RUN"
    return {
        "qkd_status": "SIMULATION_READY",
        "pqc_status": get_pqc_status()["status"],
        "communication_status": (
            "MESSAGE_SENT" if latest and latest.encrypted_message else "KEY_AVAILABLE"
        ) if latest else "NOT_STARTED",
        "interception_status": (
            "NOT_ASSESSED" if latest_key_status == "INSUFFICIENT_DATA"
            else "POSSIBLE_INTERCEPTION_DETECTED" if interception
            else "NO_INTERCEPTION_INDICATED"
        ) if latest else "NOT_ASSESSED",
        "latest_key_status": latest_key_status,
        "latest_session_id": latest.session_id if latest else None,
        "pqc": get_pqc_status(),
        "last_comparison": state.last_comparison,
    }


@app.post("/api/bb84/run")
def run_bb84_endpoint(
    request: BB84RunRequest,
    reveal_key: bool = Query(default=False),
) -> dict[str, Any]:
    """Run BB84, keep its raw key server-side, and return display-safe data."""
    started = time.perf_counter()
    result_object = run_bb84_qiskit(
        n_qubits=request.n_qubits,
        seed=request.seed,
        attack=request.attack,
        intercept_fraction=request.intercept_fraction,
        qber_sample_fraction=request.qber_sample_fraction,
        qber_threshold=request.qber_threshold,
        noise_probability=request.noise_probability,
    )
    result_dict = _plain_result(result_object)
    session = state.create_session(result_dict)
    elapsed = time.perf_counter() - started
    return _response_for_run(session, elapsed, reveal_key)


@app.get("/api/bb84/{session_id}/circuit")
@app.get("/api/sessions/{session_id}/circuit")
def get_circuit(session_id: str) -> dict[str, Any]:
    """Generate normal and optional attack circuit images lazily on request."""
    session = _require_session(session_id)
    result = session.result
    if "normal" not in session.circuit_cache:
        normal = build_display_circuit(
            result["alice_bits"],
            result["alice_bases"],
            result["bob_bases"],
            max_qubits=CIRCUIT_POSITIONS,
        )
        session.circuit_cache["normal"] = {
            "png_base64": circuit_to_png_base64(normal),
            "text": circuit_to_text(normal),
        }
    response: dict[str, Any] = {"normal": session.circuit_cache["normal"]}
    if result["attack_enabled"]:
        if "attack" not in session.circuit_cache:
            attack = build_attack_display_circuit(
                result["alice_bits"],
                result["alice_bases"],
                result["eve_bases"] or [],
                result["bob_bases"],
                max_qubits=CIRCUIT_POSITIONS,
            )
            session.circuit_cache["attack"] = {
                "png_base64": circuit_to_png_base64(attack),
                "text": circuit_to_text(attack),
            }
        response["attack"] = session.circuit_cache["attack"]
    return response


@app.post("/api/message/send")
def message_send(request: MessageSendRequest) -> dict[str, Any]:
    """Encrypt the actual message using Alice's accepted final key."""
    session = _require_session(request.session_id)
    if not state.consume_session(session.session_id):
        raise HTTPException(
            status_code=409,
            detail="This key was already used. Run a new BB84 round for the next message.",
        )
    try:
        encrypted = send_secure_message(session.result, request.message)
    except (KeyNotAcceptedError, KeyTooShortError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    session.encrypted_message = encrypted
    return {
        "session_id": session.session_id,
        "encrypted_message": encrypted.to_dict(),
        "sender_fingerprint": key_fingerprint(session.result["alice_final_key"]),
        "message_status": "ENCRYPTED_SENT",
    }


@app.post("/api/message/receive")
def message_receive(request: MessageReceiveRequest) -> dict[str, Any]:
    """Decrypt the stored envelope using Bob's own final key copy."""
    session = _require_session(request.session_id)
    if session.encrypted_message is None:
        raise HTTPException(status_code=409, detail="No encrypted message is stored for this session.")
    try:
        message = receive_secure_message(session.result, session.encrypted_message)
    except (KeyNotAcceptedError, KeyTooShortError, DecryptionError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    alice_fingerprint = key_fingerprint(session.result["alice_final_key"])
    bob_fingerprint = key_fingerprint(session.result["bob_final_key"])
    return {
        "session_id": session.session_id,
        "message": message,
        "receiver_fingerprint": bob_fingerprint,
        "fingerprints_match": alice_fingerprint == bob_fingerprint,
        "message_status": "DECRYPTED_RECEIVED",
    }


def _message_steps(
    *,
    message_length: int,
    result: dict[str, Any],
    accepted: bool,
    blocked_reason: str | None,
    timing_seconds: dict[str, float],
) -> list[dict[str, Any]]:
    """Create the 13-stage trace with live values from this actual run."""
    data = result
    qkd_status = "done" if result else "pending"
    decision_status = "done" if accepted else "blocked"
    return [
        _step(1, "Message entered", "The trimmed text and route are validated.", "Avoids encrypting an invalid payload.", "done", {"characters": message_length}, timing_seconds.get("validation")),
        _step(2, "Random bits generated", "Alice generates fresh random BB84 bits.", "This per-message run provides independent key material.", qkd_status, {"qubits": len(data.get("alice_bits", []))}),
        _step(3, "Random bases chosen", "Alice and Bob independently choose Z/X bases.", "Matching choices can contribute to the sifted key.", qkd_status, {"alice": _compact(data.get("alice_bases", []), 32), "bob": _compact(data.get("bob_bases", []), 32)}),
        _step(4, "Qubits prepared", "The simulator constructs the BB84 preparation and measurement circuits.", "The basis choices define the simulated key-establishment round.", qkd_status, {"simulator": "Qiskit Aer", "circuit_positions": len(data.get("alice_bits", []))}),
        _step(5, "Quantum transmission", "Simulated qubits traverse the channel; Eve is included only when requested.", "Interception or channel noise may introduce errors.", qkd_status, {"attack": data.get("attack_enabled", False), "intercept_fraction": data.get("intercept_fraction", 0.0), "noise_probability": data.get("noise_probability", 0.0)}),
        _step(6, "Receiver measures", "Bob measures each simulated qubit using his chosen basis.", "These measurements produce Bob's candidate bits.", qkd_status, {"measured_positions": len(data.get("bob_bits", []))}),
        _step(7, "Bases compared and key sifted", "Positions with different bases are discarded.", "Only matching, unsampled positions can contribute to the final key.", qkd_status, {"matching": len(data.get("matching_positions", [])), "sifted_length": data.get("sifted_length", 0)}),
        _step(8, "QBER sample checked", "A public sample is compared to estimate errors.", "Publicly sampled bits are excluded from message-key material.", qkd_status, {"sample_size": data.get("sample_size", 0), "sample_qber": data.get("qber_sample_qber", 0.0)}),
        _step(9, "Security decision", "The sampled QBER is compared with the configured threshold.", "Only an ACCEPTED and sufficiently long key may protect a message.", decision_status, {"key_status": data.get("key_status"), "reason": blocked_reason or data.get("reason")}, timing_seconds.get("bb84")),
        _step(10, "Session key derived and message encrypted", "HKDF derives an AES key; AES-GCM authenticates and encrypts the actual message.", "Encryption uses route-bound authenticated data.", "done" if accepted else "blocked", {"cipher": "AES-256-GCM", "aad": f"{data.get('sender', '')} -> {data.get('receiver', '')}"}, timing_seconds.get("encryption")),
        _step(11, "Ciphertext sent", "The encrypted envelope is associated with this one-use session.", "Ciphertext and public nonce/salt metadata travel separately from the BB84 key.", "done" if accepted else "blocked", {"ciphertext_available": accepted}),
        _step(12, "Receiver decrypts", "The receiver authenticates and decrypts using its own key copy.", "GCM authentication prevents accepting modified or wrong-route ciphertext.", "done" if accepted else "blocked", {"fingerprints_match": accepted}),
        _step(13, "Message delivered or withheld", "The receiver gets the original text only after successful key acceptance and authentication.", "Rejected or insufficient keys never produce ciphertext.", "done" if accepted else "blocked", {"delivered": accepted, "reason": blocked_reason}, timing_seconds.get("decryption")),
    ]


def _message_bb84_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Return the per-message BB84 display data, excluding key bits."""
    names = ["alice_bits", "alice_bases", "bob_bases", "bob_bits", "matching_mask"]
    arrays = {name: _array_summary(result[name]) for name in names}
    errors = [
        bool(result["matching_mask"][index] and result["alice_bits"][index] != result["bob_bits"][index])
        for index in range(len(result["alice_bits"]))
    ]
    arrays["error_flags"] = _array_summary(errors)
    if result["attack_enabled"]:
        for name in ("eve_bases", "eve_bits", "intercepted_mask"):
            arrays[name] = _array_summary(result.get(name) or [])
    return {
        "arrays": arrays,
        "matching_positions": result["matching_positions"][:DISPLAY_POSITIONS],
        "matching_positions_count": len(result["matching_positions"]),
        "qubits_transmitted": len(result["alice_bits"]),
        "sifted_length": result["sifted_length"],
        "sample_size": result["sample_size"],
        "final_key_length": result["final_key_length"],
        "sample_qber": result["qber_sample_qber"],
        "full_sifted_qber_analysis_only": result["qber_full_sifted"],
        "key_status": result["key_status"],
        "interception_flag": result["interception_flag"],
        "reason": result["reason"],
    }


@app.post("/api/messages/send")
def send_message_pipeline(request: MessagePipelineRequest) -> dict[str, Any]:
    """Establish a fresh BB84 key for this message, then encrypt/decrypt its envelope."""
    started = time.perf_counter()
    sender, receiver = _validate_route(request.sender, request.receiver)
    validation_seconds = time.perf_counter() - started
    result: dict[str, Any] = {}
    retry_count = 0
    bb84_seconds = 0.0
    reason = ""

    for attempt in range(3):
        run_started = time.perf_counter()
        run_seed = request.seed + attempt if request.seed is not None else None
        result = _plain_result(
            run_bb84_qiskit(
                n_qubits=request.n_qubits,
                seed=run_seed,
                attack=request.attack,
                intercept_fraction=request.intercept_fraction,
                qber_sample_fraction=0.25,
                qber_threshold=0.11,
                noise_probability=request.noise_probability,
            )
        )
        bb84_seconds += time.perf_counter() - run_started
        retry_count = attempt
        result["sender"] = sender["name"]
        result["receiver"] = receiver["name"]
        result["noise_probability"] = request.noise_probability
        final_key_length = len(result["alice_final_key"])

        if result["key_status"] == "REJECTED":
            reason = result["reason"]
            break
        if result["key_status"] == "ACCEPTED" and final_key_length >= 64:
            reason = result["reason"]
            break
        reason = (
            f"Fresh BB84 round had status {result['key_status']} and a {final_key_length}-bit final key; "
            "at least 64 bits and an ACCEPTED decision are required."
        )
        if attempt < 2:
            continue

    message_id = str(uuid4())
    session = state.create_session(result)
    session.sender = sender["name"]
    session.receiver = receiver["name"]
    blocked = result["key_status"] != "ACCEPTED" or len(result["alice_final_key"]) < 64
    if result["key_status"] == "REJECTED":
        blocked = True
        reason = result["reason"]

    envelope = None
    receiver_data = None
    encryption_seconds = 0.0
    decryption_seconds = 0.0
    if not blocked:
        aad = f"{sender['name']} -> {receiver['name']}".encode("utf-8")
        if not state.consume_session(session.session_id):
            raise HTTPException(
                status_code=409,
                detail="This key was already used. Run a new BB84 round for the next message.",
            )
        encrypt_started = time.perf_counter()
        encrypted = send_secure_message(result, request.message, aad=aad)
        encryption_seconds = time.perf_counter() - encrypt_started
        session.encrypted_message = encrypted
        decrypt_started = time.perf_counter()
        recovered = receive_secure_message(result, encrypted)
        decryption_seconds = time.perf_counter() - decrypt_started
        alice_fingerprint = key_fingerprint(result["alice_final_key"])
        bob_fingerprint = key_fingerprint(result["bob_final_key"])
        envelope = encrypted.to_dict()
        receiver_data = {
            "message": recovered,
            "fingerprint": bob_fingerprint,
            "fingerprints_match": alice_fingerprint == bob_fingerprint,
        }
    else:
        alice_fingerprint = key_fingerprint(result["alice_final_key"])
        bob_fingerprint = key_fingerprint(result["bob_final_key"])

    total_seconds = time.perf_counter() - started
    timing_seconds = {
        "validation": validation_seconds,
        "bb84_key_establishment": bb84_seconds,
        "encryption": encryption_seconds,
        "decryption": decryption_seconds,
        "total": total_seconds,
    }
    summary = _message_bb84_summary(result)
    step_trace = _message_steps(
        message_length=len(request.message),
        result=result,
        accepted=not blocked,
        blocked_reason=reason if blocked else None,
        timing_seconds={
            "validation": validation_seconds,
            "bb84": bb84_seconds,
            "encryption": encryption_seconds,
            "decryption": decryption_seconds,
        },
    )
    response: dict[str, Any] = {
        "message_id": message_id,
        "session_id": session.session_id,
        "sender": sender["name"],
        "receiver": receiver["name"],
        "step_trace": step_trace,
        "timings_seconds": timing_seconds,
        "bb84": summary,
        "matching_count": summary["matching_positions_count"],
        "sifted_length": summary["sifted_length"],
        "sample_size": summary["sample_size"],
        "final_key_length": summary["final_key_length"],
        "sample_qber": summary["sample_qber"],
        "full_sifted_qber_analysis_only": summary["full_sifted_qber_analysis_only"],
        "key_status": summary["key_status"],
        "interception_flag": summary["interception_flag"],
        "reason": reason,
        "retries": retry_count,
        "key_fingerprints": {"alice": alice_fingerprint, "bob": bob_fingerprint},
        "blocked": blocked,
    }
    if blocked:
        response["withheld"] = True
    else:
        response["envelope"] = envelope
        response["receiver"] = receiver_data

    history = {
        "message_id": message_id,
        "session_id": session.session_id,
        "time": datetime.now(timezone.utc).isoformat(),
        "sender": sender["name"],
        "receiver": receiver["name"],
        "message_preview": request.message[:72],
        "key_fingerprint": alice_fingerprint,
        "matching_count": summary["matching_positions_count"],
        "qber": summary["sample_qber"],
        "decision": summary["key_status"],
        "ciphertext_prefix": envelope["ciphertext"][:24] if envelope else "",
        "blocked": blocked,
    }
    state.store_message(MessageRecord(message_id, session.session_id, response, history))
    return response


@app.get("/api/messages")
def list_messages() -> dict[str, Any]:
    """Return up to the latest 20 route-aware message-history entries."""
    return {"messages": state.list_messages(20)}


@app.get("/api/messages/{message_id}")
def get_message(message_id: str) -> dict[str, Any]:
    """Return the full trace for one message attempt."""
    record = state.get_message(message_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Message was not found.")
    return record.details


@app.delete("/api/messages")
def clear_messages() -> dict[str, int]:
    """Clear in-memory message history."""
    count = len(state.list_messages(200))
    state.clear_messages()
    return {"cleared": count}


def _comparison_job(request: ComparisonRequest) -> dict[str, Any]:
    return run_comparison(
        runs=request.runs,
        n_qubits=request.n_qubits,
        base_seed=request.base_seed,
        qber_sample_fraction=request.qber_sample_fraction,
        qber_threshold=request.qber_threshold,
        intercept_fraction=request.intercept_fraction,
    )


@app.post("/api/experiments/compare", status_code=202)
def compare_experiments(request: ComparisonRequest) -> dict[str, str]:
    """Start a comparison in a daemon thread and return its job ID."""
    job = _launch_job(lambda: _comparison_job(request), cache_result="comparison")
    return {"job_id": job.job_id, "status": "running"}


@app.post("/api/experiments/detection-vs-qubits", status_code=202)
def compare_detection_vs_qubits(request: DetectionVsQubitsRequest) -> dict[str, str]:
    """Start a detection-rate versus qubit-count job in a daemon thread."""
    if any(count < 8 or count > 512 for count in request.qubit_counts):
        raise HTTPException(status_code=422, detail="Each qubit count must be between 8 and 512.")
    job = _launch_job(
        lambda: detection_rate_vs_qubits(
            qubit_counts=request.qubit_counts,
            runs=request.runs,
            base_seed=request.base_seed,
            qber_sample_fraction=request.qber_sample_fraction,
            qber_threshold=request.qber_threshold,
            intercept_fraction=request.intercept_fraction,
        ),
        cache_result="detection",
    )
    return {"job_id": job.job_id, "status": "running"}


@app.get("/api/experiments/last")
def get_last_experiment() -> dict[str, Any]:
    """Return the most recently completed comparison, if one is cached."""
    return {"result": state.last_comparison}


@app.get("/api/experiments/last-detection")
def get_last_detection() -> dict[str, Any]:
    """Return the most recently completed detection-versus-qubits result."""
    return {"result": state.last_detection}


@app.get("/api/experiments/{job_id}")
def get_experiment_job(job_id: str) -> dict[str, Any]:
    """Return the progress and result for a background job."""
    snapshot = state.snapshot_job(job_id)
    if snapshot is None:
        raise HTTPException(status_code=404, detail="Experiment job was not found.")
    return snapshot


_FRONTEND_DIR = Path(__file__).resolve().parents[2] / "frontend"
if _FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=_FRONTEND_DIR, html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("PORT", "8000"))
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=port)

