from .opensearch_client import client

from config import OPENSEARCH_INDEX


dimension = 1024


index_body = {
    "settings": {
        "index": {
            "knn": True
        }
    },
    "mappings": {
        "properties": {

            "content": {
                "type": "text"
            },

            "embedding": {
                "type": "knn_vector",
                "dimension": dimension
            },

            "source": {
                "type": "keyword"
            },

            "category": {
                "type": "keyword"
            }
        }
    }
}


if client.indices.exists(
    index=OPENSEARCH_INDEX
):

    print("Index already exists")

else:

    response = client.indices.create(
        index=OPENSEARCH_INDEX,
        body=index_body
    )

    print(response)