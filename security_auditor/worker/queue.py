"""Background job queue for the Django-integrated dashboard.

Jobs run in an in-process thread pool and track
QUEUED/RUNNING/SUCCESS/FAILED status; no external broker is required.
"""
from __future__ import annotations

import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Job:
    job_id: str
    kind: str
    status: str = "QUEUED"
    error: str | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    finished_at: str | None = None


class JobQueue:
    def __init__(self, max_workers: int = 2):
        self._pool = ThreadPoolExecutor(max_workers=max_workers,
                                        thread_name_prefix="audit-worker")
        self.jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._counter = 0

    def submit(self, kind: str, fn, *args, **kwargs) -> Job:
        with self._lock:
            self._counter += 1
            job = Job(job_id=f"job-{self._counter:04d}", kind=kind)
            self.jobs[job.job_id] = job

        def runner():
            job.status = "RUNNING"
            try:
                fn(*args, **kwargs)
                job.status = "SUCCESS"
            except Exception as exc:  # noqa: BLE001
                job.error = f"{exc}\n{traceback.format_exc(limit=5)}"
                job.status = "FAILED"   # status last: observers see error with FAILED
            finally:
                job.finished_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

        self._pool.submit(runner)
        return job

    def get(self, job_id: str) -> Job | None:
        return self.jobs.get(job_id)

    def list(self) -> list[dict]:
        return [{"job_id": j.job_id, "kind": j.kind, "status": j.status,
                 "created_at": j.created_at, "finished_at": j.finished_at,
                 "error": (j.error or "")[:300] or None} for j in self.jobs.values()]
