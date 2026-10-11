# SecureAI Guard

**Agentic AI Security Analyst & Incident Response Platform**

SecureAI Guard is a Python-based security investigation and controlled
incident-response project combining LangGraph orchestration,
retrieval-augmented generation (RAG), AWS security tools exposed through
MCP, risk assessment, human approval, policy enforcement,
DynamoDB-backed idempotency, and audit events.

> **Status:** Core backend components are implemented and several
> isolated tests pass. The graph-level approved-path mock test currently
> has a `KeyError: 'policy_decision'`. The project is not yet
> production-ready, and a complete real-AWS remediation flow has not
> been verified. `TAG_RESOURCE` is the only currently implemented AWS
> write action.

## Contents

-   [Goals](#goals)
-   [Status](#status)
-   [Architecture](#architecture)
-   [Repository structure](#repository-structure)
-   [Technology stack](#technology-stack)
-   [Prerequisites and setup](#prerequisites-and-setup)
-   [Configuration](#configuration)
-   [Run MCP servers](#run-mcp-servers)
-   [Tests](#tests)
-   [Workflow](#workflow)
-   [MCP tools and actions](#mcp-tools-and-actions)
-   [AWS resources](#aws-resources)
-   [Security considerations](#security-considerations)
-   [Known limitations](#known-limitations)
-   [Roadmap](#roadmap)
-   [Troubleshooting](#troubleshooting)

## Goals

-   Investigate security alerts using a structured agent workflow.
-   Retrieve relevant security knowledge from OpenSearch.
-   Gather evidence using read-only security tools.
-   Assess risk and confidence before recommending an action.
-   Require human approval for HIGH and CRITICAL risk paths.
-   Enforce centralized policy checks before remediation.
-   Reduce duplicate action execution using DynamoDB idempotency.
-   Record investigation, approval, policy, and action events in
    DynamoDB.
-   Keep read-only investigation tools separate from action-capable
    tools.

## Status

  -----------------------------------------------------------------------
  Component                           Current status
  ----------------------------------- -----------------------------------
  LangGraph workflow and state        Implemented; approved-path graph
                                      test still needs fixing

  Planner, RAG, investigation, risk   Implemented/configured; broader
  nodes                               validation remains

  OpenSearch `security-knowledge`     Existing and accessible
  index                               

  Hybrid retrieval and reranking      Integrated/configured;
                                      relevance/load testing remains

  Read-only Security MCP              EC2, CloudTrail, GuardDuty lookup
                                      tools implemented

  Action MCP                          Separate server; `TAG_RESOURCE` AWS
                                      write handler implemented

  Human approval interrupt            Implemented; isolated test passes

  Policy engine                       Implemented with demo tenant/action
                                      rules

  DynamoDB audit                      Implemented; approval/policy/action
                                      event integration

  DynamoDB idempotency                Claim, in-progress conflict,
                                      success replay and failure state

  Unit tests                          Several isolated tests pass

  Graph mock test                     Rejection path passes; approved
                                      path currently fails on
                                      `policy_decision` lookup

  Real AWS remediation end-to-end     Not verified

  API/dashboard deployment            Not confirmed complete

  Production hardening                Pending
  -----------------------------------------------------------------------

## Architecture

``` mermaid
flowchart TD
    A[Security alert or user query] --> B[LangGraph Planner]
    B --> C[RAG: OpenSearch hybrid retrieval]
    C --> D[Investigation Agent]
    D <--> E[Read-only Security MCP]
    E --> F[EC2 / CloudTrail / GuardDuty evidence]
    F --> D
    D --> G[Risk Assessment]
    G -->|LOW / MEDIUM| H[Final response]
    G -->|HIGH / CRITICAL| I[Human Approval]
    I -->|Rejected| H
    I -->|Approved| J[Action Controller]
    J --> K[Policy Engine]
    K -->|Deny or audit failure| H
    K -->|Allow| L[DynamoDB Idempotency]
    L --> M[Action Executor]
    M --> N[Action MCP]
    N --> O[AWS: currently TAG_RESOURCE]
    M --> P[DynamoDB Audit Trail]
    I --> P
    K --> P
```

### Flow

1.  Planner interprets the incoming request.
2.  RAG retrieves relevant knowledge from OpenSearch.
3.  Investigation gathers evidence through read-only MCP tools.
4.  Risk assessment assigns risk/confidence and recommends an action.
5.  HIGH/CRITICAL cases enter the human approval interrupt.
6.  Rejection stops the workflow before the action controller.
7.  Approved requests are validated by the controller and policy engine.
8.  The policy decision is audited; failure to persist that decision
    denies execution.
9.  The executor claims an idempotency key before dispatching a
    supported action.
10. Action lifecycle events are recorded in DynamoDB.

LOW/MEDIUM risk currently ends at the graph's final-response path; this
is a workflow choice, not proof that an incident was remediated.

## Repository structure

These are the relevant files confirmed in the current implementation;
this may not be the complete repository listing.

``` text
secure_ai_agent/
├── agents/
│   ├── state.py
│   ├── planner.py
│   ├── rag.py
│   ├── investigation.py
│   ├── risk.py
│   ├── approval.py
│   ├── action.py
│   ├── action_executor.py
│   ├── graph.py
│   ├── test_approval_audit.py
│   ├── test_policy_audit.py
│   ├── test_action_controller.py
│   ├── test_action_executor.py
│   ├── test_graph_mock.py
│   └── test_data.py
├── mcp_server/
│   ├── security_server.py
│   └── action_server.py
├── policy/
│   └── engine.py
└── storage/
    ├── audit.py
    ├── idempotency.py
    └── test_idempotency.py
```

## Technology stack

-   Python
-   LangGraph
-   Amazon Bedrock, configured model `amazon.nova-micro-v1:0`
-   Amazon Titan Embeddings v2
-   Amazon OpenSearch Serverless
-   Hybrid BM25/vector retrieval
-   `BAAI/bge-reranker-base`
-   Model Context Protocol (MCP), Streamable HTTP
-   AWS SDK for Python (`boto3`)
-   DynamoDB
-   Python tests and asynchronous mocks

Pin exact dependency versions before a production release.

## Prerequisites and setup

PowerShell commands below assume Windows.

``` powershell
cd E:\ai-video\codetech\tutorials\secure_ai_agent
.\.venv\Scripts\Activate.ps1
python --version
aws sts get-caller-identity
aws configure get region
```

If the repository contains `requirements.txt`:

``` powershell
python -m pip install -r requirements.txt
```

Resolve dependency/Python compatibility issues rather than blindly
upgrading every package in a working environment. Never commit
credentials or `.env` files.

## Configuration

Known development settings:

  Setting                   Value / note
  ------------------------- -----------------------------
  AWS region                `us-east-1`
  Bedrock model             `amazon.nova-micro-v1:0`
  Embeddings                Amazon Titan Embeddings v2
  OpenSearch index          `security-knowledge`
  Read-only MCP             `http://127.0.0.1:8000/mcp`
  Action MCP                `http://127.0.0.1:8001/mcp`
  Audit table               `secure-ai-audit`
  Idempotency table         `secure-ai-idempotency`
  Audit actor fallback      `secure-ai-agent`
  Demo tenant allowlist     `default`
  Demo minimum confidence   `0.60`

Check the actual environment-variable names in `storage/audit.py`,
`storage/idempotency.py`, and the MCP modules before setting variables.
For example, only if the code reads these names:

``` powershell
$env:AWS_REGION = "us-east-1"
$env:AUDIT_TABLE_NAME = "secure-ai-audit"
$env:IDEMPOTENCY_TABLE_NAME = "secure-ai-idempotency"
```

The application uses the configured AWS SDK credential chain. Confirm
the active identity and region before any write operation.

## Run MCP servers

Start each server in a separate PowerShell window:

``` powershell
python -m mcp_server.security_server
```

``` powershell
python -m mcp_server.action_server
```

Configured endpoints:

-   Read-only Security MCP: `http://127.0.0.1:8000/mcp`
-   Action MCP: `http://127.0.0.1:8001/mcp`

Use actual startup output as the source of truth if the entry point
differs. Do not expose the action MCP server publicly without
authentication, authorization, network restrictions, and secure
transport.

The graph factory is asynchronous (`create_security_graph`). Invoke it
through the project's runner/API entry point if one exists. A complete
API or dashboard entry point is not confirmed as complete.

## Tests

Run isolated tests from the repository root:

``` powershell
python -m storage.test_idempotency
python -m agents.test_approval_audit
python -m agents.test_policy_audit
python -m agents.test_action_controller
python -m agents.test_action_executor
```

Graph mock test:

``` powershell
python -m py_compile agents/test_graph_mock.py
python -m agents.test_graph_mock
```

The rejection path has passed. The approved path currently fails with:

``` text
KeyError: 'policy_decision'
```

The executor may replace `action_result` with its own output. Preserve
the policy decision in a separate graph-state field or assert it at the
controller's actual output location. Also mock
`agents.action_executor.record_audit_event` in this test if it must not
write test events to real DynamoDB.

A passing mock test is not proof of successful real AWS remediation.

## Workflow details

### Human approval

`agents/approval.py` uses LangGraph's interrupt/resume flow and captures
`APPROVED`/`REJECTED`, approver metadata, and a reason. It emits
`APPROVAL_REQUESTED` and `APPROVAL_DECISION` audit events. The action
controller requires an approved status.

### Policy engine

`policy/engine.py` currently checks items including:

-   Tenant allowlist (`default` in the demo policy).
-   Supported action name.
-   Minimum confidence threshold (`0.60`).
-   Risk and approval requirements.
-   Resource identifier.
-   Idempotency key.
-   Approval metadata for high-risk actions.

This is a demo policy, not a complete production RBAC/ABAC system.

### Idempotency

`storage/idempotency.py` uses a conditional DynamoDB claim to prevent
concurrent workers claiming the same key. A completed successful request
can return its stored result; an in-progress duplicate is blocked. Stale
`IN_PROGRESS` recovery is pending. Exactly-once execution across
distributed AWS systems is not guaranteed.

### Audit

`storage/audit.py` supports events including:

-   `ALERT_RECEIVED`
-   `INVESTIGATION_STARTED`
-   `INVESTIGATION_COMPLETED`
-   `RISK_ASSESSED`
-   `APPROVAL_REQUESTED`
-   `APPROVAL_DECISION`
-   `POLICY_DECISION`
-   `ACTION_REQUESTED`
-   `ACTION_STARTED`
-   `ACTION_COMPLETED`
-   `ACTION_FAILED`

Some audit writes are best-effort. The action controller denies
execution if the policy-decision audit write fails. Define which events
must be durable before production use. Audit lookup currently uses
`Scan`; indexed queries are needed for scale.

## MCP tools and supported actions

### Read-only tools

`mcp_server/security_server.py` exposes:

-   `get_ec2_instance`
-   `get_cloudtrail_events`
-   `get_guardduty_findings`

Valid resource identifiers and relevant AWS data are required. EC2 and
GuardDuty test resources have not yet been created for this project, so
placeholder IDs can yield empty or unhelpful evidence.

### Action tools

The current real AWS write handler supports:

-   `TAG_RESOURCE`

The policy module may list `ISOLATE_INSTANCE`, `BLOCK_IP`, and
`DISABLE_ACCESS_KEY`, but those are not operational until real handlers,
permission boundaries, validation, execution tests, and recovery
procedures are implemented.

## AWS resources

  -----------------------------------------------------------------------
  Resource                            Status / details
  ----------------------------------- -----------------------------------
  Region                              `us-east-1`

  DynamoDB `secure-ai-audit`          ACTIVE; PK `tenant_id` (String), SK
                                      `event_id` (String)

  DynamoDB `secure-ai-idempotency`    ACTIVE; PK `idempotency_key`
                                      (String)

  OpenSearch Serverless               Existing endpoint accessible

  OpenSearch index                    `security-knowledge` exists

  EC2 test resource                   Not created

  GuardDuty test finding              Not created/available for this
                                      project
  -----------------------------------------------------------------------

The AWS account was verified during development, but do not embed
account IDs in a public README. Verify the active account using
`aws sts get-caller-identity`.

### Cost-conscious development

-   Run mocks before creating cloud resources.
-   Avoid leaving paid services running unnecessarily.
-   Check current pricing and resource state before experiments.
-   Use least-privilege IAM permissions.
-   Do not test remediation against production resources.

## Security considerations

Before production use:

1.  Authenticate users/services and authorize every tenant, incident,
    and action.
2.  Enforce tenant isolation across graph state, retrieval, audit
    queries, idempotency, and authorization.
3.  Separate read-only investigation IAM permissions from remediation
    permissions.
4.  Bind approval to the exact incident, action, resource, and request
    version; expire stale approvals.
5.  Revalidate resource ownership/state immediately before execution.
6.  Implement idempotency lease expiry, crash recovery, and
    ambiguous-outcome reconciliation.
7.  Define audit durability, indexed queries, retention, and tamper
    resistance.
8.  Store secrets securely and never hardcode credentials.
9.  Restrict MCP network access; do not expose unauthenticated action
    endpoints.
10. Add structured logs, metrics, tracing, alarms, and operational
    dashboards.
11. Treat alerts, retrieved documents, and tool outputs as untrusted;
    defend against prompt injection and unsafe tool instructions.
12. Add concurrency, timeout, retry, negative, and failure-injection
    tests.
13. Keep human approval for consequential actions and provide an
    emergency stop.

This is a development project, not a certified security product. Do not
use it as the sole control for production incident response.

## Known limitations

-   Approved-path graph mock test has a `policy_decision` assertion
    mismatch.
-   The graph mock test should mock executor audit writes if real
    DynamoDB writes are not intended.
-   Tenant ID is not yet fully typed/enforced across all state and data
    paths.
-   Policy is a demo policy, not complete production authorization.
-   Only `TAG_RESOURCE` has a real AWS write handler.
-   No valid EC2/GuardDuty resources have been created for end-to-end
    investigation testing.
-   Stale `IN_PROGRESS` idempotency recovery is pending.
-   Audit lookup uses `Scan`.
-   Some audit paths are best-effort.
-   Full API/dashboard deployment and production operational controls
    are not confirmed complete.
-   RAG quality, load capacity, and real AWS remediation require broader
    tests.

## Roadmap

1.  Fix `agents/test_graph_mock.py` so rejection and approved paths both
    pass.
2.  Add a separate `policy_decision` field to graph state and preserve
    it through execution.
3.  Mock audit writes in isolated tests; keep intentional DynamoDB
    integration tests separate.
4.  Add graph tests for policy denial, audit failure, executor failure,
    and malformed approval.
5.  Implement stale idempotency lease/recovery and concurrency tests.
6.  Add typed tenant state and enforce tenant isolation end to end.
7.  Implement additional remediation handlers only after defining
    permissions and approval rules.
8.  Verify `TAG_RESOURCE` against a dedicated low-cost AWS test
    resource.
9.  Replace audit scans with indexed queries and establish retention.
10. Add deployment automation, monitoring, alerting, secrets management,
    and API/dashboard integration.
11. Complete security review, failure-injection tests, and load tests
    before production.

## Troubleshooting

### `KeyError: 'policy_decision'`

The executor may overwrite `action_result`. Inspect the final graph
state and preserve policy decision in a separate field rather than
assuming it remains in the executor result.

### DynamoDB rejects floating-point values

DynamoDB's Python serializer does not accept normal Python floats. The
audit layer should recursively convert finite floats to `Decimal` and
reject `NaN`/infinity.

### Investigation returns low confidence or no findings

Verify that valid EC2 instance IDs, relevant CloudTrail events, and real
GuardDuty finding IDs are being used. Placeholder identifiers do not
validate the real investigation flow.

### Duplicate action request is blocked

An `IN_PROGRESS` idempotency record blocks another request with the same
key. Inspect the record and use a defined recovery procedure before
changing or deleting it. Do not blindly retry an action whose outcome is
uncertain.

### AWS access errors

``` powershell
aws sts get-caller-identity
aws configure get region
```

Verify active credentials, region, IAM permissions, and resource names.
Do not grant broad administrator access as a troubleshooting shortcut.

## License

No license has been specified in the current project context. Add a
`LICENSE` file before publishing or distributing the repository.

## Disclaimer

SecureAI Guard is under active development. Components described as
implemented may still require integration, security, and operational
validation. Use mocks and isolated development resources until the
complete workflow has been verified.
