from .opensearch_client import client

from config import OPENSEARCH_INDEX


query = "CloudTrail IAM changes"


search_body = {

    "size": 5,

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