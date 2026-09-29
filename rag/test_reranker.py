from .hybrid_search import hybrid_rerank_search


query = """
How should I investigate suspicious EC2 activity
and determine whether credentials were compromised?
"""


results = hybrid_rerank_search(
    query=query,
    candidate_k=20,
    top_k=5
)


print("\n")
print("=" * 80)
print("FINAL RERANKED RESULTS")
print("=" * 80)


for index, document in enumerate(
    results,
    start=1
):

    print(f"\n#{index}")

    print(
        "Rerank Score:",
        document["rerank_score"]
    )

    print(
        "Source:",
        document.get("source")
    )

    print(
        "Category:",
        document.get("category")
    )

    print(
        "Content:",
        document["content"]
    )

    print("-" * 80)