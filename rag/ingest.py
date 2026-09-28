from pathlib import Path

from langchain_aws import BedrockEmbeddings
from langchain_text_splitters import (
    RecursiveCharacterTextSplitter
)

from .opensearch_client import client

from config import OPENSEARCH_INDEX, AWS_REGION, BEDROCK_EMBEDDING_MODEL_ID


embeddings = BedrockEmbeddings(
    model_id=BEDROCK_EMBEDDING_MODEL_ID,
    region_name=AWS_REGION
)


splitter = RecursiveCharacterTextSplitter(
    chunk_size=500,
    chunk_overlap=100
)


def ingest_documents():

    files = list(
        Path("docs").glob("*.txt")
    )

    print(
        f"Found {len(files)} files"
    )

    total_chunks = 0


    for file_path in files:

        print(
            f"Processing: {file_path.name}"
        )


        text = file_path.read_text(
            encoding="utf-8"
        )


        chunks = splitter.split_text(
            text
        )


        for chunk in chunks:

            vector = embeddings.embed_query(
                chunk
            )


            document = {

                "content": chunk,

                "embedding": vector,

                "source": file_path.name,

                "category": file_path.stem,

                "tenant_id": "default"
            }


            response = client.index(
                index=OPENSEARCH_INDEX,
                body=document
            )


            total_chunks += 1


            print(
                f"Indexed: "
                f"{response['_id']}"
            )


    print(
        f"\nTotal chunks indexed: "
        f"{total_chunks}"
    )


if __name__ == "__main__":

    ingest_documents()