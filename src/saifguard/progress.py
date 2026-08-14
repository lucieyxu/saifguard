import logging
import queue
import threading

LOGGER = logging.getLogger(__name__)

_LOCK = threading.Lock()
_SESSION_QUEUES: dict[str, queue.Queue] = {}
_LATEST_QUEUE: queue.Queue | None = None


def set_progress_queue(q: queue.Queue | None, session_id: str = None):
    """Set the active progress queue."""
    global _LATEST_QUEUE
    with _LOCK:
        _LATEST_QUEUE = q
        if session_id:
            if q is not None:
                _SESSION_QUEUES[session_id] = q
            else:
                _SESSION_QUEUES.pop(session_id, None)


def emit_progress(msg: str, session_id: str = None):
    """Emit a human-readable progress indicator to the active stream."""
    clean_msg = msg.strip()
    if not clean_msg.startswith("*progress*:"):
        clean_msg = f"*progress*: {clean_msg}"

    target_q = None
    with _LOCK:
        if session_id and session_id in _SESSION_QUEUES:
            target_q = _SESSION_QUEUES[session_id]
        else:
            target_q = _LATEST_QUEUE

    if target_q is not None:
        target_q.put(clean_msg)
        LOGGER.info(f"Emitted progress: {clean_msg}")
    else:
        LOGGER.info(f"Progress (no queue attached): {clean_msg}")
