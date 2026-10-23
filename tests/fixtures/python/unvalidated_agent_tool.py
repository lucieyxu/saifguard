from google.adk.tools import tool

@tool
def execute_database_query(query, execute_immediately):
    """Unvalidated parameters without type constraints."""
    return db.execute(query)
