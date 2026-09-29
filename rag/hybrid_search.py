from .opensearch_client import client
from .embeddings import embeddings
from .reranker import DocumentReranker

from config import OPENSEARCH_INDEX


# --------------------------------------------------
# BM25 SEARCH
# --------------------------------------------------

def bm25_search(
    query: str,
    k: int = 20
):

    body = {
        "size": k,
        "query": {
            "multi_match": {
                "query": query,
                "fields": [
                    "content"
                ]
            }
        }
    }

    response = client.search(
        index=OPENSEARCH_INDEX,
        body=body
    )

    results = []

    for hit in response["hits"]["hits"]:

        results.append({
            "id": hit["_id"],
            "content": hit["_source"]["content"],
            "source": hit["_source"].get("source"),
            "category": hit["_source"].get("category"),
            "tenant_id": hit["_source"].get("tenant_id"),
            "bm25_score": hit["_score"]
        })

    return results


# --------------------------------------------------
# VECTOR SEARCH
# --------------------------------------------------

def vector_search(
    query: str,
    k: int = 20
):

    query_vector = embeddings.embed_query(query)

    body = {
        "size": k,
        "query": {
            "knn": {
                "embedding": {
                    "vector": query_vector,
                    "k": k
                }
            }
        }
    }

    response = client.search(
        index=OPENSEARCH_INDEX,
        body=body
    )

    results = []

    for hit in response["hits"]["hits"]:

        results.append({
            "id": hit["_id"],
            "content": hit["_source"]["content"],
            "source": hit["_source"].get("source"),
            "category": hit["_source"].get("category"),
            "tenant_id": hit["_source"].get("tenant_id"),
            "vector_score": hit["_score"]
        })

    return results


# --------------------------------------------------
# DEDUPLICATION
# --------------------------------------------------

def deduplicate(
    documents: list
):

    unique = {}

    for document in documents:

        document_id = document["id"]

        if document_id not in unique:

            unique[document_id] = document

        else:

            # Merge scores when same document
            # came from BM25 + vector search

            existing = unique[document_id]

            if "bm25_score" in document:
                existing["bm25_score"] = document[
                    "bm25_score"
                ]

            if "vector_score" in document:
                existing["vector_score"] = document[
                    "vector_score"
                ]

    return list(unique.values())


# --------------------------------------------------
# HYBRID SEARCH
# --------------------------------------------------

def hybrid_search(
    query: str,
    candidate_k: int = 20
):

    bm25_results = bm25_search(
        query,
        k=candidate_k
    )

    vector_results = vector_search(
        query,
        k=candidate_k
    )

    candidates = deduplicate(
        bm25_results + vector_results
    )

    return candidates


# --------------------------------------------------
# HYBRID + RERANK
# --------------------------------------------------

def hybrid_rerank_search(
    query: str,
    candidate_k: int = 20,
    top_k: int = 5
):

    print("\n[1] Running BM25 + Vector search...")

    candidates = hybrid_search(
        query=query,
        candidate_k=candidate_k
    )

    print(
        f"Candidates found: {len(candidates)}"
    )

    print("\n[2] Running reranker...")

    reranker = DocumentReranker()

    ranked_documents = reranker.rerank(
        query=query,
        documents=candidates,
        top_k=top_k
    )

    return ranked_documents