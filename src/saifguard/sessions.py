"""Vertex AI Agent Platform session management for SAIFGuard."""

import asyncio
import logging
import threading
import uuid

from google.adk.sessions import InMemorySessionService, VertexAiSessionService
from saifguard.config import (
    AGENT_RUNTIME_ID,
    APP_NAME,
    PROJECT_ID,
    REGION,
    VERTEX_LOCATION,
)

LOGGER = logging.getLogger(__name__)


class SessionManager:
    """Manages Vertex AI Agent Platform session operations, asynchronous event loop, and message retrieval."""

    def __init__(
        self,
        project_id: str = PROJECT_ID,
        vertex_location: str = VERTEX_LOCATION,
        region: str = REGION,
        agent_runtime_id: str = AGENT_RUNTIME_ID,
        app_name: str = APP_NAME,
    ):
        self.project_id = project_id
        self.agent_runtime_id = agent_runtime_id
        # For local dev / testing, agent_runtime_id may be None
        self.app_name = agent_runtime_id if agent_runtime_id else app_name
        # Agent Platform Sessions doesn't support the "global" location
        self.session_location = region if vertex_location == "global" else vertex_location

        try:
            self.session_service = VertexAiSessionService(
                project=self.project_id,
                location=self.session_location,
                agent_engine_id=self.agent_runtime_id,
            )
            LOGGER.debug(
                f"Initialized Agent Platform Session Service for project={self.project_id}, location={self.session_location}"
            )
        except Exception as e:
            LOGGER.warning(
                f"Could not initialize Agent Platform Session Service: {e}. Falling back to InMemorySessionService."
            )
            self.session_service = InMemorySessionService()

        # Dedicated persistent background event loop for async SessionService calls
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name="saifguard-session-worker"
        )
        self._thread.start()

    def _run_async(self, coro):
        """Run async SessionService coroutines on the persistent background event loop."""
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def create_session(self, user_id: str, title: str = None) -> str:
        """Create a new session and return its valid session ID."""
        state_dict = {"title": title} if title else {}
        try:
            session = self._run_async(
                self.session_service.create_session(
                    app_name=self.app_name, user_id=str(user_id), state=state_dict
                )
            )
            if session and hasattr(session, "id"):
                return str(session.id)
        except Exception as e:
            LOGGER.warning(f"Could not create session in session service: {e}. Generating local session ID.")
        return f"session_{uuid.uuid4().hex[:10]}"

    async def _list_sessions_async(self, user_id: str) -> list[dict]:
        """Fetch past sessions and resolve first query titles in parallel."""
        res = await self.session_service.list_sessions(app_name=self.app_name, user_id=str(user_id))
        sessions = getattr(res, "sessions", res) or []
        if not sessions:
            return []

        async def _enrich_session(s):
            s_id = getattr(s, "id", None) or getattr(s, "session_id", str(s))
            update_time = getattr(s, "last_update_time", None)
            state = getattr(s, "state", {}) or {}
            title = state.get("title")

            if not title:
                try:
                    full_session = await self.session_service.get_session(
                        app_name=self.app_name,
                        user_id=str(user_id),
                        session_id=str(s_id),
                    )
                    if full_session and hasattr(full_session, "events") and full_session.events:
                        for ev in full_session.events:
                            if hasattr(ev, "content") and ev.content and getattr(ev.content, "role", "") == "user":
                                parts = getattr(ev.content, "parts", []) or []
                                t = "".join([str(getattr(p, "text", "")) for p in parts if getattr(p, "text", None)]).strip()
                                if t:
                                    lines = [line.strip() for line in t.splitlines() if line.strip()]
                                    clean = lines[0].lstrip("#* `>-").strip() if lines else t
                                    title = clean[:32].rsplit(" ", 1)[0] if len(clean) > 32 else clean
                                    break
                except Exception:
                    pass

            if not title:
                title = f"Session {str(s_id)[:8]}"

            return {
                "session_id": str(s_id),
                "last_update_time": update_time,
                "title": title,
            }

        results = await asyncio.gather(*[_enrich_session(s) for s in sessions])
        return sorted(results, key=lambda x: x.get("last_update_time") or 0, reverse=True)

    def list_sessions(self, user_id: str) -> list[dict]:
        """List past sessions for a user with intelligent query title."""
        try:
            return self._run_async(self._list_sessions_async(user_id))
        except Exception as e:
            LOGGER.error(f"Error listing sessions for user {user_id}: {e}")
            return []

    def get_session_messages(self, user_id: str, session_id: str) -> list[dict]:
        """Fetch past message events for a given session."""
        if not session_id:
            return []
        effective_session_id = str(session_id).strip()
        try:
            session = self._run_async(
                self.session_service.get_session(
                    app_name=self.app_name, user_id=str(user_id), session_id=effective_session_id
                )
            )
            if session and hasattr(session, "events") and session.events:
                messages = []
                for event in session.events:
                    if hasattr(event, "content") and event.content:
                        role = "user" if getattr(event.content, "role", "") == "user" else "bot"
                        parts = getattr(event.content, "parts", []) or []
                        text_content = "".join(
                            [str(getattr(p, "text", "")) for p in parts if hasattr(p, "text") and p.text is not None]
                        ).strip()
                        if text_content:
                            messages.append({
                                "role": role,
                                "content": text_content,
                                "timestamp": "",
                            })
                return messages
        except Exception as e:
            LOGGER.error(f"Error retrieving session {effective_session_id} for user {user_id}: {e}")
        return []

    def delete_session(self, user_id: str, session_id: str) -> bool:
        """Delete a given session."""
        try:
            self._run_async(
                self.session_service.delete_session(
                    app_name=self.app_name, user_id=str(user_id), session_id=str(session_id)
                )
            )
            return True
        except Exception as e:
            LOGGER.error(f"Error deleting session {session_id}: {e}")
            return False
