from langchain_aws import BedrockEmbeddings

from config import BEDROCK_EMBEDDING_MODEL_ID, AWS_REGION


embeddings = BedrockEmbeddings(
    model_id=BEDROCK_EMBEDDING_MODEL_ID,
    region_name=AWS_REGION
)
