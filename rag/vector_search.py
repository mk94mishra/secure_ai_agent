from langchain_aws import BedrockEmbeddings

from .opensearch_client import client

from config import OPENSEARCH_INDEX, BEDROCK_EMBEDDING_MODEL_ID, AWS_REGION


embeddings = BedrockEmbeddings(
    model_id=BEDROCK_EMBEDDING_MODEL_ID,
    region_name=AWS_REGION
)


query = """
How do I investigate suspicious
EC2 access?
"""


query_vector = embeddings.embed_query(
    query
)


search_body = {

    "size": 5,

    "query": {

        "knn": {

            "embedding": {

                "vector": query_vector,

                "k": 5
            }
        }
    }
}


response = client.search(
    index=OPENSEARCH_INDEX,
    body=search_body
)


for hit in response["hits"]["hits"]:

    print("=" * 60)

    print(
        "Score:",
        hit["_score"]
    )

    print(
        "Source:",
        hit["_source"]["source"]
    )

    print(
        "Content:",
        hit["_source"]["content"]
    )