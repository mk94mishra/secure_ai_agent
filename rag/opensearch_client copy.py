import boto3

from opensearchpy import (
    OpenSearch,
    RequestsHttpConnection,
    AWSV4SignerAuth,
)

from config import AWS_REGION, OPENSEARCH_ENDPOINT


# ============================================================
# CONFIG
# ============================================================

INDEX_NAME = "secure-ai-test"


# ============================================================
# AWS SESSION
# ============================================================

session = boto3.Session(region_name=AWS_REGION)

sts = session.client("sts")

identity = sts.get_caller_identity()

print("================================")
print("AWS ACCOUNT :", identity["Account"])
print("AWS ARN     :", identity["Arn"])
print("AWS REGION  :", AWS_REGION)
print("ENDPOINT    :", OPENSEARCH_ENDPOINT)
print("================================")


# ============================================================
# CREDENTIALS
# ============================================================

credentials = session.get_credentials()

if credentials is None:
    raise RuntimeError("AWS credentials NOT FOUND")

print("Credentials found")


# ============================================================
# SIGV4
# ============================================================

auth = AWSV4SignerAuth(
    credentials,
    AWS_REGION,
    "aoss",
)


# ============================================================
# OPENSEARCH CLIENT
# ============================================================

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
print("Testing index:", INDEX_NAME)

try:

    exists = client.indices.exists(
        index=INDEX_NAME
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