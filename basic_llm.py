from langchain_aws import ChatBedrockConverse

from config import AWS_REGION, BEDROCK_MODEL_ID


def create_llm():

    return ChatBedrockConverse(
        model=BEDROCK_MODEL_ID,
        region_name=AWS_REGION,
        temperature=0
    )


def main():

    llm = create_llm()

    response = llm.invoke(
        "Explain RAG in simple terms."
    )

    print("\nAI Response:\n")
    print(response.content)


if __name__ == "__main__":
    main()