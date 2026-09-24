import os
from dotenv import load_dotenv

load_dotenv()


AWS_REGION = os.getenv(
    "AWS_REGION",
    "us-east-1"
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