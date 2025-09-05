import logging
import traceback
import asyncio
from dotenv import load_dotenv

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from models.query_request import QueryRequest
from saifguard.agent import SAIFGuardAgent

load_dotenv()
logging.basicConfig(level=logging.INFO)



app = FastAPI(
    title="SAIFGuard Agent API",
    description="An API to interact with the SAIFGuard ADK Agent.",
    version="1.0.0",
)


# For now single user and single session
USER_ID, SESSION_ID = "user1", "session1"
agent = SAIFGuardAgent()

@app.on_event("startup")
async def startup_event():
    """
    Setup session at startup
    """
    print("Application starting up...")
    await agent.create_session(user_id=USER_ID, session_id=SESSION_ID)



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
        response = agent.invoke(
            message=request.message,
        )
        return StreamingResponse(response, media_type="text/plain")

    except Exception as e:
        print(f"Error during agent invocation: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=500, detail=str(e))
