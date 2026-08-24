"""Progress event dispatcher for thread- and session-isolated streaming in SAIFGuard."""

import contextvars
import logging
import queue
import threading

LOGGER = logging.getLogger(__name__)

_LOCK = threading.Lock()
_SESSION_QUEUES: dict[str, queue.Queue] = {}
_CURRENT_PROGRESS_QUEUE: contextvars.ContextVar[queue.Queue | None] = contextvars.ContextVar(
    "current_progress_queue", default=None
)


def set_progress_queue(q: queue.Queue | None, session_id: str = None) -> contextvars.Token:
    """Register the progress queue for a session and current execution context."""
    token = _CURRENT_PROGRESS_QUEUE.set(q)
    if session_id:
        with _LOCK:
            if q is not None:
                _SESSION_QUEUES[session_id] = q
            else:
                _SESSION_QUEUES.pop(session_id, None)
    return token


def reset_progress_queue(token: contextvars.Token | None = None, session_id: str = None) -> None:
    """Reset the progress queue context variable and clean up session registry."""
    if token is not None:
        try:
            _CURRENT_PROGRESS_QUEUE.reset(token)
        except Exception:
            _CURRENT_PROGRESS_QUEUE.set(None)
    else:
        _CURRENT_PROGRESS_QUEUE.set(None)

    if session_id:
        with _LOCK:
            _SESSION_QUEUES.pop(session_id, None)


def emit_progress(msg: str, session_id: str = None) -> None:
    """Emit a human-readable progress indicator to the active stream."""
    clean_msg = msg.strip()
    if not clean_msg.startswith("*progress*:"):
        clean_msg = f"*progress*: {clean_msg}"

    target_q = None

    # 1. If explicit session_id is provided, route strictly to that session's queue
    if session_id:
        with _LOCK:
            target_q = _SESSION_QUEUES.get(session_id)

    # 2. Otherwise, check contextvar (same thread / execution context)
    if target_q is None and not session_id:
        target_q = _CURRENT_PROGRESS_QUEUE.get()

    if target_q is not None:
        target_q.put(clean_msg)
        LOGGER.info(f"Emitted progress (session={session_id}): {clean_msg}")
    else:
        LOGGER.warning(f"Progress dropped (no matching queue for session={session_id}): {clean_msg}")
