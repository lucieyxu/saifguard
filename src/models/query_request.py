from pydantic import BaseModel


class QueryRequest(BaseModel):
    """Defines the structure of the incoming request body."""
    user_id: str
    message: str
    session_id: str | None = None
    model: str | None = None
