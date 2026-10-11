from rag.hybrid_search import (
    hybrid_rerank_search
)

from agents.state import AgentState


def rag_node(
    state: AgentState
):

    query = state["query"]

    documents = hybrid_rerank_search(
        query=query,
        top_k=5
    )

    context = []

    for doc in documents:

        context.append(
            {
                "content": doc.get(
                    "content",
                    ""
                ),
                "source": doc.get(
                    "source",
                    "unknown"
                ),
                "score": doc.get(
                    "score",
                    0
                )
            }
        )

    return {
        "context": context
    }