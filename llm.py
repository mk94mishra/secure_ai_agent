import os

from dotenv import load_dotenv
from langchain_aws import ChatBedrockConverse

from tools import TOOLS
from config import BEDROCK_MODEL_ID, AWS_REGION


llm = ChatBedrockConverse(
    model=BEDROCK_MODEL_ID,
    region_name=AWS_REGION,
    temperature=0
)

llm_with_tools = llm.bind_tools(
    TOOLS
)