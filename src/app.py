import asyncio
import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response, StreamingResponse
from models.query_request import QueryRequest
from saifguard.agent import SAIFGuardAgent
from saifguard.report_tool import get_session_report

LOGGER = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

app = FastAPI(
    title="SAIFGuard Agent API",
    description="An API to interact with the SAIFGuard ADK Agent.",
    version="1.0.0",
)

agent = SAIFGuardAgent()


@app.get("/healthcheck")
def healthcheck():
    """A simple endpoint to confirm the API is running."""
    return {"status": "SAIFGuard Agent API is running."}


@app.get("/report/{session_id}")
def download_report(session_id: str):
    """Download the generated SAIF_AUDIT_REPORT.md for a given session."""
    report_md = get_session_report(session_id)
    if not report_md:
        raise HTTPException(status_code=404, detail="No report found for this session.")
    return Response(
        content=report_md,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="SAIF_AUDIT_REPORT.md"'},
    )


@app.post("/invoke")
async def invoke_agent(request: QueryRequest):
    """Receives a user message and streams the agent's response back."""
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized.")

    try:
        response = agent.invoke(
            user_id=request.user_id,
            message=request.message,
            session_id=request.session_id,
            model=request.model,
        )
        return StreamingResponse(response, media_type="text/plain")

    except Exception as e:
        LOGGER.exception("Error during agent invocation: %s", e)
        raise HTTPException(status_code=500, detail=str(e))
