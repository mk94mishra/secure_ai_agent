from .opensearch_client import client

from config import OPENSEARCH_INDEX


response = client.search(
    index=OPENSEARCH_INDEX,
    body={
        "size": 10,
        "query": {
            "match_all": {}
        }
    }
)


for hit in response["hits"]["hits"]:

    print("=" * 60)

    print("ID:")
    print(hit["_id"])

    print("SOURCE:")
    print(
        hit["_source"]["source"]
    )

    print("CONTENT:")
    print(
        hit["_source"]["content"]
    )