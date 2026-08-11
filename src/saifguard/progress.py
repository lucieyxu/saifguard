import contextvars
import logging
import queue

LOGGER = logging.getLogger(__name__)

_PROGRESS_QUEUE: contextvars.ContextVar[queue.Queue | None] = contextvars.ContextVar(
    "progress_queue", default=None
)


def set_progress_queue(q: queue.Queue | None):
    """Set the active progress queue for the current session context."""
    _PROGRESS_QUEUE.set(q)


def emit_progress(msg: str):
    """Emit a human-readable progress indicator to the active stream."""
    q = _PROGRESS_QUEUE.get()
    if q is not None:
        q.put(f"\n\n*🔄 {msg}*\n\n")
    else:
        LOGGER.info(f"Progress: {msg}")
