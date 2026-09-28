import os
from dotenv import load_dotenv

load_dotenv()


AWS_REGION = os.getenv(
    "AWS_REGION"
)

BEDROCK_MODEL_ID = os.getenv(
    "BEDROCK_MODEL_ID"
)

BEDROCK_EMBEDDING_MODEL_ID = os.getenv(
    "BEDROCK_EMBEDDING_MODEL_ID"
)

DOCS_DIR = os.getenv(
    "DOCS_PATH"
)

OPENSEARCH_ENDPOINT = os.getenv(
    "OPENSEARCH_ENDPOINT"
)

OPENSEARCH_INDEX = os.getenv(
    "OPENSEARCH_INDEX"
)