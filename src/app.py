import asyncio
import logging

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from models.query_request import QueryRequest
from saifguard.agent import SAIFGuardAgent

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


@app.post("/invoke")
async def invoke_agent(request: QueryRequest):
    """
    Receives a user message and streams the agent's response back.
    """
    if not agent:
        raise HTTPException(status_code=500, detail="Agent not initialized.")

    try:
        response = agent.invoke(user_id=request.user_id, message=request.message)
        return StreamingResponse(response, media_type="text/plain")

    except Exception as e:
        print(f"Error during agent invocation: {e}")
        raise HTTPException(status_code=500, detail=str(e))
