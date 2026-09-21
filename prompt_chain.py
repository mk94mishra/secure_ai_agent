from langchain_core.prompts import ChatPromptTemplate
from langchain_aws import ChatBedrockConverse

from config import AWS_REGION, BEDROCK_MODEL_ID
from structured_output import SecurityAnalysis

llm = ChatBedrockConverse(
    model=BEDROCK_MODEL_ID,
    region_name=AWS_REGION,
    temperature=0
)

prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        """
        You are an enterprise SOC security analyst.

        Analyze security alerts based only on
        the provided evidence.
        """
    ),
    (
        "human",
        """
        Analyze this alert:

        {alert}
        """
    )
])

structured_llm = llm.with_structured_output(
    SecurityAnalysis
)

chain = prompt | structured_llm


response = chain.invoke({
    "alert": """
    GuardDuty detected suspicious activity
    from IP 185.x.x.x against EC2 instance.
    Severity: HIGH.
    """
})


print("\nAI RESPONSE:\n")
print(response)