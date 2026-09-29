"""Thread-safe in-memory storage for simulation sessions and experiment jobs."""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from typing import Any

from backend.app.messaging.secure_channel import EncryptedMessage


@dataclass
class SessionRecord:
    """One BB84 run and the optional encrypted actual message associated with it."""

    session_id: str
    result: dict[str, Any]
    encrypted_message: EncryptedMessage | None = None
    consumed: bool = False
    circuit_cache: dict[str, dict[str, str]] = field(default_factory=dict)
    sender: str | None = None
    receiver: str | None = None


@dataclass
class MessageRecord:
    """History entry and complete trace for one actual-message attempt."""

    message_id: str
    session_id: str
    details: dict[str, Any]
    history: dict[str, Any]


@dataclass
class JobRecord:
    """Lifecycle state for one background experiment job."""

    job_id: str
    status: str = "running"
    progress: float = 0.0
    result: dict[str, Any] | None = None
    error: str | None = None


class DashboardState:
    """Small process-local session/job store protected by one re-entrant lock."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.sessions: dict[str, SessionRecord] = {}
        self.messages: dict[str, MessageRecord] = {}
        self.message_order: list[str] = []
        self.jobs: dict[str, JobRecord] = {}
        self.latest_session_id: str | None = None
        self.last_comparison: dict[str, Any] | None = None
        self.last_detection: dict[str, Any] | None = None

    def create_session(self, result: dict[str, Any]) -> SessionRecord:
        """Store a result and return its unpredictable session identifier."""
        with self._lock:
            session_id = str(uuid.uuid4())
            record = SessionRecord(session_id=session_id, result=result)
            self.sessions[session_id] = record
            self.latest_session_id = session_id
            return record

    def get_session(self, session_id: str) -> SessionRecord | None:
        """Look up a BB84 session without exposing the backing dictionary."""
        with self._lock:
            return self.sessions.get(session_id)

    def consume_session(self, session_id: str) -> bool:
        """Atomically mark a session key as used once; return whether it was fresh."""
        with self._lock:
            record = self.sessions.get(session_id)
            if record is None or record.consumed:
                return False
            record.consumed = True
            return True

    def store_message(self, record: MessageRecord) -> None:
        """Store a message record, newest first, retaining up to 200 entries."""
        with self._lock:
            self.messages[record.message_id] = record
            self.message_order.insert(0, record.message_id)
            for expired_id in self.message_order[200:]:
                self.messages.pop(expired_id, None)
            del self.message_order[200:]

    def get_message(self, message_id: str) -> MessageRecord | None:
        """Return one stored message trace."""
        with self._lock:
            return self.messages.get(message_id)

    def list_messages(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return newest history rows first."""
        with self._lock:
            return [self.messages[item].history.copy() for item in self.message_order[:limit]]

    def clear_messages(self) -> None:
        """Clear the message history while leaving BB84 sessions intact."""
        with self._lock:
            self.messages.clear()
            self.message_order.clear()

    def create_job(self) -> JobRecord:
        """Create a running background job."""
        with self._lock:
            job = JobRecord(job_id=str(uuid.uuid4()))
            self.jobs[job.job_id] = job
            return job

    def get_job(self, job_id: str) -> JobRecord | None:
        """Look up a job by its public identifier."""
        with self._lock:
            return self.jobs.get(job_id)

    def complete_job(
        self,
        job_id: str,
        result: dict[str, Any],
        cache: str | None = None,
    ) -> None:
        """Mark a job complete and optionally update the cached comparison."""
        with self._lock:
            job = self.jobs[job_id]
            job.result = result
            job.progress = 1.0
            job.status = "done"
            if cache == "comparison":
                self.last_comparison = result
            elif cache == "detection":
                self.last_detection = result

    def update_job_progress(self, job_id: str, progress: float) -> None:
        """Update a running job's progress within the shared lock."""
        with self._lock:
            job = self.jobs.get(job_id)
            if job is not None and job.status == "running":
                job.progress = max(0.0, min(1.0, progress))

    def fail_job(self, job_id: str, error: str) -> None:
        """Mark a job failed using a client-safe error message."""
        with self._lock:
            job = self.jobs[job_id]
            job.error = error
            job.status = "error"

    def snapshot_job(self, job_id: str) -> dict[str, Any] | None:
        """Return a JSON-ready copy of the public job state."""
        with self._lock:
            job = self.jobs.get(job_id)
            if job is None:
                return None
            return {
                "job_id": job.job_id,
                "status": job.status,
                "progress": job.progress,
                "result": job.result,
                "error": job.error,
            }


state = DashboardState()
