from pathlib import Path

def load_documents(directory="./docs") -> list:
    documents = []
    
    for file_path in Path(directory).glob("*.txt"):
        
        text = file_path.read_text(
            encoding="utf8"
        )

        documents.append({
            "source": str(file_path),
            "content": text
        })
    return documents

if __name__ == "__main__":
    docs = load_documents("./docs")
    for doc in docs:
        print("="*50)
        print(doc["source"])
        print(doc["content"])
