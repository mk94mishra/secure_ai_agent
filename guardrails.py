from langchain_core.prompts import ChatPromptTemplate
from langchain_aws import ChatBedrockConverse

from config import AWS_REGION, BEDROCK_MODEL_ID

prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        """
        You are an enterprise SOC security analyst.

        Analyze security alerts carefully.
        Do not invent evidence.
        If information is missing, explicitly say so.
        """
    ),
    (
        "human",
        """
        Analyze this security alert:

        Alert:
        {alert}

        Provide:
        1. Summary
        2. Possible threat
        3. Evidence required
        4. Recommended next investigation
        """
    )
])


llm = ChatBedrockConverse(
    model=BEDROCK_MODEL_ID,
    region_name=AWS_REGION,
    temperature=0
)


chain = prompt | llm


alert = """
GuardDuty detected suspicious activity
from IP 185.x.x.x against EC2 instance i-123456.
Severity: HIGH.
"""


response = chain.invoke({
    "alert": alert
})


print(response.content)