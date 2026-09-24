from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_core.documents import Document

from config import DOCS_DIR
from .loader import load_documents

documents = load_documents(DOCS_DIR)

splitter = RecursiveCharacterTextSplitter(
    chunk_size = 500,
    chunk_overlap = 100
)


langchain_docs = []
def splitted_chunks() -> list:
    for doc in documents:

        doc_chunks = splitter.split_text(
            doc["content"]
        )

        for chunk in doc_chunks:
            print("metdata")
            print(doc["source"])
            langchain_docs.append(
                Document(
                    page_content=chunk,
                    metadata={
                        "source":doc["source"]
                    }
                )
            )
    return langchain_docs

if __name__ == "__main__":
    print(splitted_chunks())
    for chunk in langchain_docs:
        print("\n\n")
        print("="*60)
        print(chunk.page_content)
    