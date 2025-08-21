from pydantic import BaseModel


class QueryRequest(BaseModel):
    """Defines the structure of the incoming request body."""
    user_id: str
    message: str
