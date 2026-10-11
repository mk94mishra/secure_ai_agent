import os

import boto3
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()

AWS_REGION = os.getenv(
    "AWS_REGION",
    "us-east-1"
)


# ============================================================
# MCP SERVER
# ============================================================

mcp = FastMCP(
    "secure-ai-security",
    instructions="""
    Read-only AWS security investigation tools.

    These tools can inspect AWS security data.

    They do NOT:
    - modify AWS resources
    - terminate EC2 instances
    - modify security groups
    - change IAM permissions
    - delete resources
    - perform remediation actions
    """
)


# ============================================================
# AWS CLIENTS
# ============================================================

ec2 = boto3.client(
    "ec2",
    region_name=AWS_REGION
)

cloudtrail = boto3.client(
    "cloudtrail",
    region_name=AWS_REGION
)

guardduty = boto3.client(
    "guardduty",
    region_name=AWS_REGION
)


# ============================================================
# EC2
# ============================================================

@mcp.tool()
def get_ec2_instance(
    instance_id: str
) -> dict:
    """
    Get read-only information about an EC2 instance.

    Args:
        instance_id:
            Real AWS EC2 instance ID.
            Example: i-0123456789abcdef0
    """

    if not instance_id:
        return {
            "found": False,
            "error": "instance_id is required"
        }

    if not instance_id.startswith("i-"):
        return {
            "found": False,
            "error": (
                "Invalid EC2 instance ID. "
                "Expected an ID beginning with 'i-'."
            ),
            "instance_id": instance_id
        }

    try:

        response = ec2.describe_instances(
            InstanceIds=[instance_id]
        )

        reservations = response.get(
            "Reservations",
            []
        )

        if not reservations:
            return {
                "found": False,
                "message": "EC2 instance not found",
                "instance_id": instance_id
            }

        instances = reservations[0].get(
            "Instances",
            []
        )

        if not instances:
            return {
                "found": False,
                "message": "EC2 instance not found",
                "instance_id": instance_id
            }

        instance = instances[0]

        return {
            "found": True,

            "instance_id": instance.get(
                "InstanceId"
            ),

            "state": (
                instance
                .get("State", {})
                .get("Name")
            ),

            "instance_type": instance.get(
                "InstanceType"
            ),

            "private_ip": instance.get(
                "PrivateIpAddress"
            ),

            "public_ip": instance.get(
                "PublicIpAddress"
            ),

            "vpc_id": instance.get(
                "VpcId"
            ),

            "subnet_id": instance.get(
                "SubnetId"
            ),

            "availability_zone": (
                instance
                .get("Placement", {})
                .get("AvailabilityZone")
            ),

            "launch_time": str(
                instance.get("LaunchTime")
            ),

            "iam_instance_profile": (
                instance
                .get("IamInstanceProfile")
            ),
        }

    except Exception as exc:

        return {
            "found": False,
            "error": str(exc),
            "instance_id": instance_id
        }


# ============================================================
# CLOUDTRAIL
# ============================================================

@mcp.tool()
def get_cloudtrail_events(
    username: str = "",
    resource_name: str = "",
    max_results: int = 10
) -> list:
    """
    Get recent CloudTrail events.

    Can search by:
    - username
    - resource name

    This tool is READ-ONLY.
    """

    # --------------------------------------------------------
    # Validate max_results
    # --------------------------------------------------------

    max_results = min(
        max(
            max_results,
            1
        ),
        50
    )

    kwargs = {
        "MaxResults": max_results
    }

    # --------------------------------------------------------
    # Username filter
    # --------------------------------------------------------

    if username:

        kwargs["LookupAttributes"] = [
            {
                "AttributeKey": "Username",
                "AttributeValue": username
            }
        ]

    # --------------------------------------------------------
    # Resource filter
    # --------------------------------------------------------

    elif resource_name:

        kwargs["LookupAttributes"] = [
            {
                "AttributeKey": "ResourceName",
                "AttributeValue": resource_name
            }
        ]

    try:

        response = cloudtrail.lookup_events(
            **kwargs
        )

        events = []

        for event in response.get(
            "Events",
            []
        ):

            events.append(
                {
                    "event_time": str(
                        event.get("EventTime")
                    ),

                    "event_name": event.get(
                        "EventName"
                    ),

                    "username": event.get(
                        "Username"
                    ),

                    "event_source": event.get(
                        "EventSource"
                    ),

                    "resources": event.get(
                        "Resources",
                        []
                    ),
                }
            )

        return events

    except Exception as exc:

        return [
            {
                "error": str(exc),

                "username": username,

                "resource_name": resource_name
            }
        ]


# ============================================================
# GUARDDUTY
# ============================================================

@mcp.tool()
def get_guardduty_findings(
    detector_id: str,
    finding_ids: list[str]
) -> list:
    """
    Get GuardDuty findings.

    IMPORTANT:
    detector_id must be the real GuardDuty detector ID.

    finding_ids must contain real GuardDuty finding IDs.

    This tool is READ-ONLY.
    """

    # --------------------------------------------------------
    # Detector validation
    # --------------------------------------------------------

    if not detector_id:

        return [
            {
                "error":
                    "GuardDuty detector_id is required"
            }
        ]

    # --------------------------------------------------------
    # Prevent fake/default detector IDs
    # --------------------------------------------------------

    if detector_id.lower() in {
        "default",
        "unknown",
        "none",
        "null"
    }:

        return [
            {
                "error": (
                    "Invalid GuardDuty detector_id. "
                    "Use the actual GuardDuty detector ID."
                ),

                "detector_id": detector_id
            }
        ]

    # --------------------------------------------------------
    # Basic detector ID validation
    # --------------------------------------------------------

    if len(detector_id) < 10:

        return [
            {
                "error": (
                    "GuardDuty detector_id appears invalid."
                ),

                "detector_id": detector_id
            }
        ]

    # --------------------------------------------------------
    # Finding validation
    # --------------------------------------------------------

    if not finding_ids:

        return [
            {
                "error": (
                    "At least one GuardDuty "
                    "finding_id is required."
                )
            }
        ]

    # --------------------------------------------------------
    # Limit number of findings
    # --------------------------------------------------------

    finding_ids = finding_ids[:50]

    # --------------------------------------------------------
    # Prevent obvious fake/internal alert IDs
    # --------------------------------------------------------

    invalid_ids = []

    for finding_id in finding_ids:

        if not finding_id:
            invalid_ids.append(
                finding_id
            )
            continue

        if finding_id.startswith(
            "ALT-"
        ):
            invalid_ids.append(
                finding_id
            )

    if invalid_ids:

        return [
            {
                "error": (
                    "One or more finding IDs appear "
                    "to be internal alert IDs, not "
                    "GuardDuty finding IDs."
                ),

                "invalid_finding_ids":
                    invalid_ids
            }
        ]

    # --------------------------------------------------------
    # AWS API
    # --------------------------------------------------------

    try:

        response = guardduty.get_findings(
            DetectorId=detector_id,
            FindingIds=finding_ids
        )

        findings = []

        for finding in response.get(
            "Findings",
            []
        ):

            findings.append(
                {
                    "id": finding.get(
                        "Id"
                    ),

                    "type": finding.get(
                        "Type"
                    ),

                    "title": finding.get(
                        "Title"
                    ),

                    "description": finding.get(
                        "Description"
                    ),

                    "severity": finding.get(
                        "Severity"
                    ),

                    "region": finding.get(
                        "Region"
                    ),

                    "created_at": finding.get(
                        "CreatedAt"
                    ),

                    "updated_at": finding.get(
                        "UpdatedAt"
                    ),

                    "account_id": finding.get(
                        "AccountId"
                    ),
                }
            )

        return findings

    except Exception as exc:

        return [
            {
                "error": str(exc),

                "detector_id":
                    detector_id,

                "finding_ids":
                    finding_ids
            }
        ]


# ============================================================
# SERVER START
# ============================================================

if __name__ == "__main__":

    print(
        "Starting SecureAI Security MCP Server"
    )

    print(
        f"AWS Region: {AWS_REGION}"
    )

    print(
        "Transport: streamable-http"
    )

    print(
        "Endpoint: http://127.0.0.1:8000/mcp"
    )

    mcp.run(
        transport="streamable-http"
    )