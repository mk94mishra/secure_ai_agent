import os

import boto3

from requests_aws4auth import AWS4Auth
from opensearchpy import OpenSearch, RequestsHttpConnection
from config import AWS_REGION, OPENSEARCH_ENDPOINT, OPENSEARCH_INDEX


credentials = boto3.Session().get_credentials()

auth = AWS4Auth(
    credentials.access_key,
    credentials.secret_key,
    AWS_REGION,
    "aoss",
    session_token=credentials.token
)

host = OPENSEARCH_ENDPOINT.replace("https://", "").rstrip("/")

client = OpenSearch(
    hosts=[
        {
            "host": host,
            "port": 443,
        }
    ],
    http_auth=auth,
    use_ssl=True,
    verify_certs=True,
    connection_class=RequestsHttpConnection,
    timeout=30,
    max_retries=2,
    retry_on_timeout=True,
)


# ============================================================
# TEST
# ============================================================

print("\nCalling OpenSearch Serverless...")
print("Testing index:", OPENSEARCH_INDEX)

try:

    exists = client.indices.exists(
        index=OPENSEARCH_INDEX
    )

    print("\nSUCCESS")
    print("OpenSearch Serverless is reachable")
    print("Index exists:", exists)

except Exception as e:

    print("\nERROR")
    print("TYPE   :", type(e).__name__)
    print("ERROR  :", repr(e))
    print("STATUS :", getattr(e, "status_code", None))
    print("INFO   :", getattr(e, "info", None))