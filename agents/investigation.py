import json
from typing import Any

from langchain_core.messages import (
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from langgraph.prebuilt import (
    ToolNode,
    tools_condition,
)

from agents.llm import llm
from agents.mcp_client import get_mcp_tools
from agents.state import AgentState


# ============================================================
# CONFIGURATION
# ============================================================

MAX_INVESTIGATION_ITERATIONS = 4


# ============================================================
# INVESTIGATION SYSTEM PROMPT
# ============================================================

INVESTIGATION_SYSTEM_PROMPT = """
You are an AWS Security Investigation Agent.

Your job is to investigate security alerts using
READ-ONLY AWS security tools.

Available tools may include:

- get_ec2_instance
- get_cloudtrail_events
- get_guardduty_findings


============================================================
CORE RULES
============================================================

1. You are READ-ONLY.

2. Never modify AWS resources.

3. Never terminate EC2 instances.

4. Never modify security groups.

5. Never modify IAM permissions.

6. Never delete AWS resources.

7. Never perform remediation actions.

8. Use MCP tools when actual AWS information
   is required.

9. Do not invent AWS facts.

10. Clearly distinguish:

    - observed evidence
    - inference
    - uncertainty
    - failed evidence collection


============================================================
IDENTIFIER RULES
============================================================

11. If a real EC2 instance ID is available,
    investigate it using get_ec2_instance.

12. Only call GuardDuty when BOTH are available:

    - real GuardDuty detector ID
    - real GuardDuty finding ID

13. Never guess a GuardDuty detector ID.

14. Never guess a GuardDuty finding ID.

15. Never use "default" as a GuardDuty detector ID.

16. Never use "unknown" as a GuardDuty detector ID.

17. Never use an internal alert ID such as
    "ALT-1001" as a GuardDuty finding ID unless
    the alert explicitly identifies it as a GuardDuty
    finding ID.

18. If a required identifier is missing,
    do not invent one.

19. If a tool reports that an identifier is invalid,
    do not retry the same tool with the same argument.

20. If a tool returns an error, record the error as
    evidence_collection_failure.


============================================================
TOOL LOOP RULES
============================================================

21. Do not repeatedly call the same tool with
    exactly the same arguments.

22. Before calling a tool, check whether the same
    tool call has already failed.

23. If the same call already failed, stop that
    investigation path.

24. Do not call tools unnecessarily.

25. Stop investigating once sufficient evidence
    has been collected.

26. If evidence is insufficient because an AWS
    identifier is missing, clearly report that
    limitation instead of guessing.


============================================================
INVESTIGATION OBJECTIVE
============================================================

Collect enough reliable evidence to help the Risk
Agent determine:

- what happened
- which AWS resource is involved
- whether suspicious activity is observed
- what evidence supports the alert
- what evidence could not be collected
- what remains uncertain


============================================================
RAG CONTEXT
============================================================

Security knowledge retrieved through RAG is reference
knowledge.

RAG does NOT represent current AWS state.

MCP tool results represent live AWS evidence.

Do not confuse the two.


============================================================
FINAL INVESTIGATION BEHAVIOR
============================================================

When sufficient evidence has been collected:

- stop calling tools
- summarize the investigation
- do not claim confirmed compromise without
  supporting evidence
"""


# ============================================================
# LOAD MCP TOOLS
# ============================================================

async def load_investigation_tools():
    """
    Load read-only security tools from MCP server.
    """

    return await get_mcp_tools()


# ============================================================
# CONTENT NORMALIZATION
# ============================================================

def content_to_text(
    content: Any
) -> str:
    """
    Convert LangChain message content into text.
    """

    if isinstance(content, str):
        return content

    try:
        return json.dumps(
            content,
            default=str
        )
    except Exception:
        return str(content)


# ============================================================
# JSON PARSER
# ============================================================

def try_parse_json(
    content: str
):
    """
    Try converting tool response into Python object.
    """

    try:
        return json.loads(content)
    except Exception:
        return None


# ============================================================
# TOOL ERROR DETECTION
# ============================================================

def is_tool_error(
    parsed: Any
) -> bool:
    """
    Detect whether an MCP tool returned an error.
    """

    if not isinstance(
        parsed,
        dict
    ):
        return False

    return bool(
        parsed.get("error")
    )


# ============================================================
# EVIDENCE EXTRACTION
# ============================================================

def extract_tool_evidence(
    messages: list
) -> list[dict[str, Any]]:
    """
    Extract MCP ToolMessage results and convert them
    into structured evidence.
    """

    evidence = []

    for message in messages:

        if not isinstance(
            message,
            ToolMessage
        ):
            continue

        tool_name = getattr(
            message,
            "name",
            "unknown_tool"
        )

        content = content_to_text(
            getattr(
                message,
                "content",
                ""
            )
        )

        parsed = try_parse_json(
            content
        )

        # ----------------------------------------------------
        # ERROR RESPONSE
        # ----------------------------------------------------

        if is_tool_error(parsed):

            evidence.append(
                {
                    "source": "MCP",
                    "tool": tool_name,
                    "status": "error",
                    "error": parsed.get("error"),
                    "data": parsed,
                }
            )

            continue

        # ----------------------------------------------------
        # SUCCESS RESPONSE
        # ----------------------------------------------------

        evidence.append(
            {
                "source": "MCP",
                "tool": tool_name,
                "status": "success",
                "data": (
                    parsed
                    if parsed is not None
                    else content
                ),
            }
        )

    return evidence


# ============================================================
# TOOL CALL SIGNATURE
# ============================================================

def tool_call_signature(
    tool_name: str,
    args: dict
) -> tuple:

    try:

        serialized_args = json.dumps(
            args,
            sort_keys=True,
            default=str
        )

    except Exception:

        serialized_args = str(args)

    return (
        tool_name,
        serialized_args
    )


# ============================================================
# PREVIOUS TOOL CALL DETECTION
# ============================================================

def get_previous_tool_calls(
    messages: list
) -> set:
    """
    Extract tool calls from PREVIOUS AI messages.

    Important:
    We only use messages that occurred before
    the current AI response.
    """

    previous_calls = set()

    for message in messages:

        tool_calls = getattr(
            message,
            "tool_calls",
            None
        )

        if not tool_calls:
            continue

        for tool_call in tool_calls:

            tool_name = tool_call.get(
                "name"
            )

            args = tool_call.get(
                "args",
                {}
            )

            previous_calls.add(
                tool_call_signature(
                    tool_name,
                    args
                )
            )

    return previous_calls


# ============================================================
# INVALID CALL DETECTION
# ============================================================

def has_invalid_identifier(
    tool_name: str,
    args: dict
) -> bool:
    """
    Detect obvious invalid AWS arguments.
    """

    # --------------------------------------------------------
    # EC2
    # --------------------------------------------------------

    if tool_name == "get_ec2_instance":

        instance_id = args.get(
            "instance_id"
        )

        if not instance_id:
            return True

        if not str(
            instance_id
        ).startswith("i-"):
            return True

    # --------------------------------------------------------
    # GuardDuty
    # --------------------------------------------------------

    if tool_name == "get_guardduty_findings":

        detector_id = args.get(
            "detector_id"
        )

        finding_ids = args.get(
            "finding_ids"
        )

        if not detector_id:
            return True

        if str(
            detector_id
        ).lower() in {
            "default",
            "unknown",
            "none",
            "null",
        }:
            return True

        if not finding_ids:
            return True

        for finding_id in finding_ids:

            if not finding_id:
                return True

            if str(
                finding_id
            ).startswith("ALT-"):
                return True

    return False


# ============================================================
# INVESTIGATION NODE
# ============================================================

async def investigation_node(
    state: AgentState
):
    """
    Main Investigation Agent.

    The LLM decides which read-only MCP tool to call.
    """

    # --------------------------------------------------------
    # Iteration
    # --------------------------------------------------------

    iteration = state.get(
        "investigation_iterations",
        0
    )

    # --------------------------------------------------------
    # Safety limit
    # --------------------------------------------------------

    if iteration >= MAX_INVESTIGATION_ITERATIONS:

        return {
            "investigation_iterations": iteration
        }

    # --------------------------------------------------------
    # Load MCP tools
    # --------------------------------------------------------

    tools = await load_investigation_tools()

    # --------------------------------------------------------
    # Bind tools to Bedrock
    # --------------------------------------------------------

    model = llm.bind_tools(
        tools
    )

    # --------------------------------------------------------
    # Read state
    # --------------------------------------------------------

    alert = state.get(
        "alert",
        {}
    )

    query = state.get(
        "query",
        ""
    )

    context = state.get(
        "context",
        []
    )

    messages = state.get(
        "messages",
        []
    )

    existing_evidence = state.get(
        "evidence",
        []
    )

    # --------------------------------------------------------
    # RAG context
    # --------------------------------------------------------

    context_parts = []

    for item in context:

        source = item.get(
            "source",
            "unknown"
        )

        content = item.get(
            "content",
            ""
        )

        context_parts.append(
            f"""
SOURCE:
{source}

CONTENT:
{content}
"""
        )

    context_text = "\n".join(
        context_parts
    )

    # --------------------------------------------------------
    # Previous tool calls
    # --------------------------------------------------------

    previous_tool_calls = (
        get_previous_tool_calls(
            messages
        )
    )

    # --------------------------------------------------------
    # Build investigation request
    # --------------------------------------------------------

    investigation_request = f"""
Investigate the following security alert.

============================================================
CURRENT ITERATION
============================================================

{iteration + 1}

Maximum allowed iterations:

{MAX_INVESTIGATION_ITERATIONS}


============================================================
SECURITY ALERT
============================================================

{json.dumps(
    alert,
    indent=2,
    default=str
)}


============================================================
INVESTIGATION QUERY
============================================================

{query}


============================================================
RAG SECURITY KNOWLEDGE
============================================================

{context_text}


============================================================
PREVIOUS EVIDENCE
============================================================

{json.dumps(
    existing_evidence,
    indent=2,
    default=str
)}


============================================================
PREVIOUS TOOL CALLS
============================================================

{json.dumps(
    list(previous_tool_calls),
    indent=2,
    default=str
)}


============================================================
TASK
============================================================

Investigate using only available READ-ONLY MCP tools.

If an identifier is missing or invalid:

- do NOT guess it
- do NOT invent it
- do NOT repeatedly retry it

If sufficient evidence has already been collected,
stop calling tools and summarize the investigation.

Clearly distinguish:

- observed evidence
- inference
- failed evidence collection
- uncertainty
"""

    # ========================================================
    # IMPORTANT BEDROCK MESSAGE ORDER
    # ========================================================
    #
    # Bedrock Converse requires the conversation to start
    # with a USER message.
    #
    # Therefore:
    #
    # SystemMessage
    #      ↓
    # HumanMessage
    #      ↓
    # Previous AI/Tool messages
    #
    # ========================================================

    messages_for_model = [
        SystemMessage(
            content=INVESTIGATION_SYSTEM_PROMPT
        ),
        HumanMessage(
            content=investigation_request
        ),
        *messages,
    ]

    # --------------------------------------------------------
    # Invoke Bedrock
    # --------------------------------------------------------

    response = await model.ainvoke(
        messages_for_model
    )

    # --------------------------------------------------------
    # IMPORTANT
    #
    # Only add the new AI response to LangGraph state.
    #
    # AgentState.messages uses add_messages,
    # therefore previous messages are preserved.
    # --------------------------------------------------------

    new_messages = [
        response
    ]

    # --------------------------------------------------------
    # Extract evidence from existing history
    # --------------------------------------------------------

    all_messages = [
        *messages,
        response
    ]

    evidence = extract_tool_evidence(
        all_messages
    )

    # --------------------------------------------------------
    # Remove duplicate evidence
    # --------------------------------------------------------

    unique_evidence = []

    seen = set()

    for item in evidence:

        try:

            key = json.dumps(
                item,
                sort_keys=True,
                default=str
            )

        except Exception:

            key = str(item)

        if key in seen:
            continue

        seen.add(key)

        unique_evidence.append(
            item
        )

    # --------------------------------------------------------
    # Return state update
    # --------------------------------------------------------

    return {
        "messages": new_messages,

        "evidence": unique_evidence,

        "investigation_iterations":
            iteration + 1,
    }


# ============================================================
# MCP TOOL NODE
# ============================================================

async def create_investigation_tool_node():
    """
    Create LangGraph ToolNode containing MCP tools.
    """

    tools = await load_investigation_tools()

    return ToolNode(
        tools
    )


# ============================================================
# ROUTING
# ============================================================

def route_investigation(
    state: AgentState
):
    """
    Decide whether to execute MCP tools or continue
    to the Risk Agent.
    """

    iteration = state.get(
        "investigation_iterations",
        0
    )

    # --------------------------------------------------------
    # Hard safety limit
    # --------------------------------------------------------

    if iteration >= MAX_INVESTIGATION_ITERATIONS:

        return "__end__"

    # --------------------------------------------------------
    # Get current messages
    # --------------------------------------------------------

    messages = state.get(
        "messages",
        []
    )

    if not messages:

        return "__end__"

    # --------------------------------------------------------
    # Last message should normally be AIMessage
    # --------------------------------------------------------

    last_message = messages[-1]

    tool_calls = getattr(
        last_message,
        "tool_calls",
        []
    )

    # --------------------------------------------------------
    # No tool calls
    # --------------------------------------------------------

    if not tool_calls:

        return "__end__"

    # --------------------------------------------------------
    # Previous messages BEFORE current AI message
    # --------------------------------------------------------

    previous_messages = messages[:-1]

    previous_tool_calls = (
        get_previous_tool_calls(
            previous_messages
        )
    )

    # --------------------------------------------------------
    # Validate requested tool calls
    # --------------------------------------------------------

    for tool_call in tool_calls:

        tool_name = tool_call.get(
            "name"
        )

        args = tool_call.get(
            "args",
            {}
        )

        # ----------------------------------------------------
        # Invalid identifier
        # ----------------------------------------------------

        if has_invalid_identifier(
            tool_name,
            args
        ):

            print(
                f"[INVESTIGATION] "
                f"Blocked invalid tool call: "
                f"{tool_name} {args}"
            )

            return "__end__"

        # ----------------------------------------------------
        # Duplicate tool call
        # ----------------------------------------------------

        signature = tool_call_signature(
            tool_name,
            args
        )

        if signature in previous_tool_calls:

            print(
                f"[INVESTIGATION] "
                f"Blocked duplicate tool call: "
                f"{tool_name} {args}"
            )

            return "__end__"

    # --------------------------------------------------------
    # Execute MCP tools
    # --------------------------------------------------------

    return "tools"