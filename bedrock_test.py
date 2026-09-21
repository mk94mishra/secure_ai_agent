import boto3
from config import AWS_REGION, BEDROCK_MODEL_ID


client = boto3.client(
    "bedrock-runtime",
    region_name=AWS_REGION
)

print("Bedrock client created successfully")