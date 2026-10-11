import asyncio
import os
from pprint import pprint

from dotenv import load_dotenv
from langgraph.types import Command

from agents.graph import create_security_graph
from agents.test_data import build_test_alert


# ============================================================
# Environment
# ============================================================

load_dotenv()


# ============================================================
# Configuration
# ============================================================

TEST_APPROVAL = os.getenv(
    "TEST_APPROVAL",
    "REJECTED",
).upper()

TEST_APPROVED_BY = os.getenv(
    "TEST_APPROVED_BY",
    "soc-analyst-001",
)

TEST_APPROVAL_REASON = os.getenv(
    "TEST_APPROVAL_REASON",
    "Approved after security investigation.",
)

TEST_TENANT_ID = os.getenv(
    "TEST_TENANT_ID",
    "default",
)


# ============================================================
# Validation
# ============================================================

if TEST_APPROVAL not in {
    "APPROVED",
    "REJECTED",
}:

    raise ValueError(
        "TEST_APPROVAL must be APPROVED or REJECTED."
    )


# ============================================================
# Print Section
# ============================================================

def print_section(
    title: str,
):
    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


# ============================================================
# Print Final Result
# ============================================================

def print_final_result(
    result: dict,
):
    print_section(
        "FINAL SECURITY AGENT RESULT"
    )

    print(
        f"Risk              : "
        f"{result.get('risk')}"
    )

    print(
        f"Confidence        : "
        f"{result.get('confidence')}"
    )

    print(
        f"Requires Approval : "
        f"{result.get('requires_approval')}"
    )

    print(
        f"Approval Status   : "
        f"{result.get('approval_status')}"
    )

    print(
        f"Approved By       : "
        f"{result.get('approved_by')}"
    )

    print(
        f"Approval Reason   : "
        f"{result.get('approval_reason')}"
    )

    print(
        f"Action Status     : "
        f"{result.get('action_status')}"
    )

    print(
        f"Action Type       : "
        f"{result.get('action_type')}"
    )

    print(
        f"Action Resource   : "
        f"{result.get('action_resource_id')}"
    )

    print(
        f"Idempotency Key   : "
        f"{result.get('action_idempotency_key')}"
    )

    print(
        f"Action Message    : "
        f"{result.get('action_message')}"
    )

    print()

    print(
        "Findings:"
    )

    findings = result.get(
        "findings",
        [],
    )

    if findings:

        for index, finding in enumerate(
            findings,
            start=1,
        ):
            print(
                f"  {index}. {finding}"
            )

    else:

        print(
            "  No findings."
        )

    print()

    print(
        "Evidence:"
    )

    evidence = result.get(
        "evidence",
        [],
    )

    if evidence:

        for index, item in enumerate(
            evidence,
            start=1,
        ):

            print(
                f"\n  Evidence #{index}"
            )

            pprint(
                item,
                indent=4,
            )

    else:

        print(
            "  No evidence."
        )

    print()

    print(
        "Action Result:"
    )

    action_result = result.get(
        "action_result"
    )

    if action_result:

        pprint(
            action_result,
            indent=4,
        )

    else:

        print(
            "  No action result."
        )

    print()

    print(
        "Final Response:"
    )

    print(
        result.get(
            "final_response",
            "No final response.",
        )
    )


# ============================================================
# Run Graph
# ============================================================

async def run_test():
    """
    End-to-end security agent test.
    """

    print_section(
        "SECURE AI GUARD - END TO END TEST"
    )

    print(
        f"Test approval     : {TEST_APPROVAL}"
    )

    print(
        f"Approved by       : {TEST_APPROVED_BY}"
    )

    print(
        f"Tenant            : {TEST_TENANT_ID}"
    )

    # --------------------------------------------------------
    # Build graph
    # --------------------------------------------------------

    print_section(
        "1. Creating Security Graph"
    )

    graph = await create_security_graph()

    print(
        "Security graph created successfully."
    )

    # --------------------------------------------------------
    # Build alert
    # --------------------------------------------------------

    alert = build_test_alert()

    # Add tenant information
    alert["tenant_id"] = TEST_TENANT_ID

    print_section(
        "2. Test Alert"
    )

    pprint(
        alert,
        indent=4,
    )

    # --------------------------------------------------------
    # Thread ID
    # --------------------------------------------------------

    alert_id = alert.get(
        "alert_id",
        "unknown",
    )

    thread_id = (
        f"incident-{alert_id}"
    )

    config = {
        "configurable": {
            "thread_id": thread_id,
        }
    }

    # --------------------------------------------------------
    # Initial state
    # --------------------------------------------------------

    initial_state = {
        "alert": alert,
        "tenant_id": TEST_TENANT_ID,
        "messages": [],
        "findings": [],
        "evidence": [],
        "investigation_iterations": 0,
    }

    # --------------------------------------------------------
    # Initial invocation
    # --------------------------------------------------------

    print_section(
        "3. Running Security Agent"
    )

    result = await graph.ainvoke(
        initial_state,
        config=config,
    )

    # --------------------------------------------------------
    # Check interrupt
    # --------------------------------------------------------

    interrupts = result.get(
        "__interrupt__"
    )

    if interrupts:

        print_section(
            "4. HUMAN APPROVAL REQUIRED"
        )

        print(
            "Graph paused for human approval."
        )

        for interrupt in interrupts:

            print()

            print(
                "Approval request:"
            )

            pprint(
                interrupt.value,
                indent=4,
            )

        # ----------------------------------------------------
        # Resume with human decision
        # ----------------------------------------------------

        print_section(
            "5. Resuming With Human Decision"
        )

        approval_payload = {
            "status": TEST_APPROVAL,
            "approved_by": TEST_APPROVED_BY,
            "reason": TEST_APPROVAL_REASON,
        }

        print(
            "Human decision:"
        )

        pprint(
            approval_payload,
            indent=4,
        )

        result = await graph.ainvoke(
            Command(
                resume=approval_payload
            ),
            config=config,
        )

    else:

        print_section(
            "4. No Human Approval Required"
        )

        print(
            "Risk did not require human approval."
        )

    # --------------------------------------------------------
    # Final result
    # --------------------------------------------------------

    print_final_result(
        result
    )

    # --------------------------------------------------------
    # Check action
    # --------------------------------------------------------

    action_status = result.get(
        "action_status"
    )

    if action_status == "SUCCESS":

        print_section(
            "ACTION EXECUTION SUCCESSFUL"
        )

        print(
            "AWS remediation action completed."
        )

    elif action_status == "DENIED":

        print_section(
            "ACTION DENIED"
        )

        print(
            result.get(
                "action_message",
                "Action was denied.",
            )
        )

    elif action_status == "FAILED":

        print_section(
            "ACTION FAILED"
        )

        print(
            result.get(
                "action_message",
                "Action execution failed.",
            )
        )

    else:

        print_section(
            "NO ACTION EXECUTED"
        )

        print(
            "No remediation action was executed."
        )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    asyncio.run(
        run_test()
    )