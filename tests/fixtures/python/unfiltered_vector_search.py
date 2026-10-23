def retrieve_context(query_text: str):
    # Missing tenant isolation filter in vector store search
    docs = vector_store.similarity_search(query_text)
    return "\n".join([d.page_content for d in docs])
