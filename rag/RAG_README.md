# RAG Module --- SecureAI Guard

This folder contains the Retrieval-Augmented Generation (RAG) and search
components used by SecureAI Guard. The module is intended to ingest
security knowledge, split documents into chunks, create embeddings,
index content, retrieve relevant passages, and optionally rerank results
before the investigation agent uses them.

> **Scope note:** This README is based on the RAG filenames visible in
> the project screenshot and the RAG architecture/configuration already
> established for SecureAI Guard. Exact function names, CLI arguments,
> environment-variable names, and every module's implementation should
> be confirmed from the source code before relying on commands below.
> This file does not claim that every listed module has been fully
> validated end to end.

## Contents

-   [Folder structure](#folder-structure)
-   [RAG workflow](#rag-workflow)
-   [Components](#components)
-   [Search strategies](#search-strategies)
-   [Models and index](#models-and-index)
-   [Setup](#setup)
-   [Suggested execution order](#suggested-execution-order)
-   [Integration with the agents](#integration-with-the-agents)
-   [Validation checklist](#validation-checklist)
-   [Troubleshooting](#troubleshooting)
-   [Known limitations and next
    steps](#known-limitations-and-next-steps)

## Folder structure

The following files and directories were visible in the project
screenshot:

``` text
rag/
├── __init__.py
├── bm25_search.py
├── create_index.py
├── embeddings.py
├── hybrid_search.py
├── ingest.py
├── list_documents.py
├── loader.py
├── metadata_filter.py
├── opensearch_client.py
├── opensearch_client copy.py
├── reranker.py
├── retriever.py
├── splitter.py
├── test_reranker.py
├── vector_search.py
├── vectorstore.py
└── faiss_index/
```

`opensearch_client copy.py` looks like a duplicate/backup filename.
Review it and remove it only after confirming it is not used. The local
`faiss_index/` directory may contain generated index artifacts; do not
commit large or sensitive generated data unless the repository
intentionally tracks it.

## RAG workflow

``` mermaid
flowchart TD
    A[Security knowledge documents] --> B[loader.py]
    B --> C[splitter.py]
    C --> D[metadata and chunk preparation]
    D --> E[embeddings.py]
    E --> F[vectorstore.py / OpenSearch index]
    F --> G1[vector_search.py]
    F --> G2[bm25_search.py]
    G1 --> H[hybrid_search.py]
    G2 --> H
    H --> I[metadata_filter.py]
    I --> J[reranker.py]
    J --> K[retriever.py]
    K --> L[Investigation / RAG agent]
```

The exact internal call sequence depends on the implementation in each
file. This diagram shows the intended conceptual workflow rather than a
guarantee that every arrow is wired exactly this way in code.

## Components

  -----------------------------------------------------------------------
  File / directory                    Intended responsibility
  ----------------------------------- -----------------------------------
  `__init__.py`                       Marks `rag` as a Python package and
                                      may expose package-level imports

  `loader.py`                         Loads source documents into a
                                      common representation

  `splitter.py`                       Splits loaded documents into chunks
                                      suitable for retrieval

  `embeddings.py`                     Creates embeddings for text chunks
                                      and queries

  `create_index.py`                   Creates/configures the search index

  `opensearch_client.py`              Builds or exposes the OpenSearch
                                      client

  `opensearch_client copy.py`         Likely a duplicate/backup; verify
                                      before deleting

  `vectorstore.py`                    Stores or accesses embedded
                                      documents

  `ingest.py`                         Coordinates document loading,
                                      chunking, embedding, and indexing

  `vector_search.py`                  Retrieves semantically similar
                                      chunks using vector similarity

  `bm25_search.py`                    Retrieves lexical matches using
                                      BM25

  `hybrid_search.py`                  Combines lexical and semantic
                                      retrieval

  `metadata_filter.py`                Applies filters based on document
                                      metadata

  `reranker.py`                       Reorders retrieved candidates by
                                      relevance

  `retriever.py`                      Provides a retrieval entry point or
                                      combines retrieval stages

  `list_documents.py`                 Lists indexed documents or stored
                                      document metadata

  `test_reranker.py`                  Tests the reranking component

  `faiss_index/`                      Local FAISS index/artifacts, if
                                      used by this project
  -----------------------------------------------------------------------

## Search strategies

### 1. Vector search

Vector search converts the query and document chunks into embeddings,
then finds chunks close to the query in embedding space. It is useful
when the query and source use different wording but express similar
meaning.

Example:

-   Query: `Suspicious access key activity`
-   Document wording:
    `An IAM credential was used from an unusual location`

A semantic search may find this relationship even when exact words
differ.

### 2. BM25 keyword search

BM25 ranks documents based on lexical matches. It is especially useful
for exact technical identifiers such as:

-   AWS event names
-   IAM action names
-   IP addresses and resource identifiers
-   MITRE ATT&CK technique IDs
-   Error codes and alert signatures

### 3. Hybrid search

Hybrid search combines lexical and vector retrieval so the system can
use both exact matching and semantic similarity. The precise
score-combination method (for example, rank fusion or weighted scores)
must be confirmed in `hybrid_search.py`.

### 4. Metadata filtering

Metadata filters can restrict results to relevant sources or categories.
For a multi-tenant security platform, tenant/access-control filters must
be enforced server-side and must not rely on an LLM to decide which
tenant's documents may be returned.

### 5. Reranking

A reranker scores the query against retrieved candidate passages and
reorders them by relevance. The project configuration previously
identified `BAAI/bge-reranker-base`; verify the actual model ID and
runtime configuration in `reranker.py`.

Reranking improves ordering, but it does not guarantee factual
correctness. Preserve document references and evaluate retrieval quality
with a representative security-query test set.

## Models and index

Known project configuration:

  -----------------------------------------------------------------------
  Setting                             Current project context
  ----------------------------------- -----------------------------------
  Search service                      Amazon OpenSearch Serverless is
                                      configured and accessible

  Index                               `security-knowledge`

  Embedding model                     Amazon Titan Embeddings v2

  Reranker configuration              `BAAI/bge-reranker-base`

  Local index directory               `faiss_index/` exists
  -----------------------------------------------------------------------

The presence of `faiss_index/` does not establish that FAISS is the
active production retrieval backend. The project also uses OpenSearch.
Confirm which backend each entry point selects, and avoid maintaining
two index paths accidentally.

Embedding model, vector dimension, index mapping, and
distance/similarity settings must be compatible. If changing the
embedding model or dimension, create/rebuild the index as appropriate
rather than mixing incompatible vectors.

## Setup

Run commands from the repository root in PowerShell:

``` powershell
cd E:\ai-video\codetech\tutorials\secure_ai_agent
.\.venv\Scripts\Activate.ps1
```

Check the module syntax:

``` powershell
python -m py_compile rag/loader.py
python -m py_compile rag/splitter.py
python -m py_compile rag/embeddings.py
python -m py_compile rag/opensearch_client.py
python -m py_compile rag/vectorstore.py
python -m py_compile rag/ingest.py
python -m py_compile rag/vector_search.py
python -m py_compile rag/bm25_search.py
python -m py_compile rag/hybrid_search.py
python -m py_compile rag/metadata_filter.py
python -m py_compile rag/reranker.py
python -m py_compile rag/retriever.py
```

These commands only check Python syntax; they do not verify credentials,
index mappings, model access, retrieval relevance, or successful
indexing.

Before running ingestion or index-creation commands, inspect the CLI and
configuration:

``` powershell
Get-Content rag/ingest.py
Get-Content rag/create_index.py
Get-Content rag/opensearch_client.py
```

Then use the entry point and arguments actually defined in those files.
This README intentionally does not invent a command-line interface that
has not been verified.

## Suggested execution order

Use this as a conceptual order; follow the real dependencies and CLI in
the source code:

1.  Confirm OpenSearch endpoint, AWS region, credentials, and
    permissions.
2.  Confirm the `security-knowledge` index mapping and vector dimension.
3.  Load a small, non-sensitive set of documents.
4.  Split documents into chunks and verify chunk text and metadata.
5.  Generate embeddings using the configured model.
6.  Ingest chunks into the intended index/vector store.
7.  Run a vector-search smoke test.
8.  Run a BM25 search smoke test.
9.  Run hybrid search and inspect combined candidates.
10. Verify metadata filters, including tenant/source restrictions if
    applicable.
11. Run reranking and inspect the order of results.
12. Test the final retriever used by `agents/rag.py`.
13. Record retrieval quality, latency, token/model cost, and failure
    behavior.

Start with a small dataset before ingesting a large corpus.

## Integration with the agents

The top-level agent workflow has a RAG node at `agents/rag.py`. The RAG
module should provide that node with relevant, bounded evidence rather
than returning an unfiltered corpus.

Recommended integration contract:

-   Accept a clear security-investigation query.
-   Retrieve a limited number of relevant chunks.
-   Apply tenant and access-control filters before returning results.
-   Preserve source identifiers/metadata for citations and auditability.
-   Handle empty results and search-service errors safely.
-   Treat retrieved content as untrusted input; documents must not
    override system policy or tool permissions.
-   Avoid sending unnecessary sensitive data to external model
    endpoints.
-   Log useful operational metadata without logging secrets or excessive
    raw security data.

Confirm the actual return type and function signature in
`rag/retriever.py` and `agents/rag.py` before changing their interface.

## Validation checklist

-   [ ] Index exists and its mapping matches the embedding dimensions.
-   [ ] Ingestion is idempotent or safely handles duplicate document
    IDs.
-   [ ] Chunking preserves important security context and source
    metadata.
-   [ ] Vector search returns relevant passages for semantic queries.
-   [ ] BM25 returns exact identifier and keyword matches.
-   [ ] Hybrid search improves or at least preserves retrieval quality.
-   [ ] Metadata filters cannot be bypassed by user-supplied query text.
-   [ ] Reranker handles empty candidate lists and model errors.
-   [ ] Retriever has a bounded result count and sensible timeouts.
-   [ ] Agent output identifies evidence sources.
-   [ ] No secrets or tenant-private content leak across retrieval
    boundaries.
-   [ ] Tests cover empty results, malformed metadata, unavailable
    OpenSearch, and model failures.
-   [ ] Indexing and search latency/cost are measured on representative
    data.

## Troubleshooting

### OpenSearch authentication or connection errors

Verify the active AWS identity, region, endpoint, network access, and
IAM/data-access policies. Do not solve connection issues by granting
broad administrator permissions.

``` powershell
aws sts get-caller-identity
aws configure get region
```

### No vector results

Check that documents were indexed, vectors exist, query embeddings use
the same model/dimension, and the index mapping matches the embedding
format.

### BM25 works but vector search fails

Inspect embedding generation, vector field mapping, vector dimensions,
and the OpenSearch query structure in `vector_search.py` and
`opensearch_client.py`.

### Search results are relevant but poorly ordered

Inspect candidate count, hybrid score-combination logic, and reranker
inputs/outputs. Use a small labelled evaluation set instead of judging
only one query.

### Metadata filter returns no documents

Check the actual indexed metadata field names and types. Do not silently
remove security/tenant filters as a workaround.

### Indexing duplicates documents

Check document IDs, deterministic chunk IDs, and upsert behavior in
`ingest.py` and `vectorstore.py`.

### FAISS and OpenSearch behave differently

Confirm which backend the application is using. The presence of a local
`faiss_index/` directory does not mean production queries use FAISS.

## Known limitations and next steps

-   The README is based on the visible file layout and known project
    configuration; exact function names and CLI flags should be verified
    against source.
-   Confirm whether FAISS is a local test backend or actively used by
    the application.
-   Review/remove the apparent duplicate `opensearch_client copy.py`
    only after checking references.
-   Add deterministic chunk IDs and safe re-ingestion behavior if not
    already present.
-   Add retrieval evaluation tests for vector, BM25, hybrid search,
    filters, and reranking.
-   Ensure tenant-aware metadata filtering is enforced before results
    reach the LLM.
-   Add timeouts, retries, bounded result counts, and graceful error
    handling.
-   Add source attribution to retrieved evidence.
-   Measure retrieval quality, latency, and cost on a representative
    security corpus.

## License

No license is specified here. Use the root project's license policy and
add a license file if this module is published independently.
