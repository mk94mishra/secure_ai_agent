from .vectorstore import vectorstore

retrieve = vectorstore.as_retriever(
    search_kwargs = {
        "k":3
    }
)

response = retrieve.invoke("How should I investigate suspicious EC2 access?")
for chunk in response:
    print(chunk.metadata['source'])
    print(chunk.page_content)

# print(retrieve.invoke( "What is Python"))