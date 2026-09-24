from langchain_core.prompts import ChatPromptTemplate
from langchain_aws import ChatBedrockConverse
from langchain_community.vectorstores import FAISS
from langchain_aws import BedrockEmbeddings

from pydantic import BaseModel, Field
from typing import Literal, Optional

from config import BEDROCK_EMBEDDING_MODEL_ID, BEDROCK_MODEL_ID, AWS_REGION


class SecurityAnalysis(BaseModel):

    severity: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL"
    ]

    summary: str
    confidence: Optional[str] = "Unknown"
    recommended_action: Optional[str] = "No action specified"


embeddings = BedrockEmbeddings(
    model_id=BEDROCK_EMBEDDING_MODEL_ID,
    region_name=AWS_REGION
)


vectorstore = FAISS.load_local(
    "rag/faiss_index",
    embeddings,
    allow_dangerous_deserialization=True
)


retriever = vectorstore.as_retriever(
    search_kwargs={
        "k": 3
    }
)


llm = ChatBedrockConverse(
    model=BEDROCK_MODEL_ID,
    region_name=AWS_REGION,
    temperature=0
)


structured_llm = llm.with_structured_output(
    SecurityAnalysis
)


prompt = ChatPromptTemplate.from_messages([
    (
        "system",
        """
        You are an enterprise SOC security analyst.

        Analyze the security alert using ONLY
        the provided security knowledge.

        Do not invent facts.

        If the knowledge does not contain enough
        information, say so in the summary.
        """
    ),
    (
        "human",
        """
        Security Knowledge:

        {context}


        Security Alert:

        {alert}


        Analyze the alert.
        """
    )
])


chain = prompt | structured_llm


alert = """
GuardDuty detected suspicious activity
from IP 185.x.x.x against EC2 instance.
Severity: HIGH.
"""


docs = retriever.invoke(alert)


context = "\n\n".join(
    doc.page_content for doc in docs
)


result = chain.invoke({
    "context": context,
    "alert": alert
})


print("\nRAG RESULT:\n")
print(result)