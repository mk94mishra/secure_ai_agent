from langchain_community.vectorstores import FAISS

from .embeddings import embeddings
from .splitter import splitted_chunks

vectorstore = FAISS.from_documents(
    splitted_chunks(),
    embeddings
)

vectorstore.save_local(
    "rag/faiss_index"
)


print("Vector store created successfully.")