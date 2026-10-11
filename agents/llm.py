import os

from dotenv import load_dotenv
from langchain_aws import ChatBedrockConverse



llm = ChatBedrockConverse(
    model="amazon.nova-micro-v1:0",
    region_name="us-east-1",
    temperature=0
)
