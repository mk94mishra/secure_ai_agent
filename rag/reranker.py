from sentence_transformers import CrossEncoder


class DocumentReranker:

    def __init__(
        self,
        model_name="BAAI/bge-reranker-base"
    ):
        print(f"Loading reranker model: {model_name}")

        self.model = CrossEncoder(model_name)

        print("Reranker model loaded.")

    def rerank(
        self,
        query: str,
        documents: list,
        top_k: int = 5
    ):
        """
        Rerank documents using a cross-encoder model.

        Args:
            query: User/security query
            documents: Candidate documents
            top_k: Number of final documents

        Returns:
            Top ranked documents
        """

        if not documents:
            return []

        # Query + document pairs
        pairs = [
            [query, document["content"]]
            for document in documents
        ]

        # Calculate relevance scores
        scores = self.model.predict(pairs)

        ranked_documents = []

        for document, score in zip(
            documents,
            scores
        ):

            item = document.copy()

            item["rerank_score"] = float(score)

            ranked_documents.append(item)

        # Highest relevance first
        ranked_documents.sort(
            key=lambda x: x["rerank_score"],
            reverse=True
        )

        return ranked_documents[:top_k]