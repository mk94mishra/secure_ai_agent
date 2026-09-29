import boto3

# from mcp.server.mcpserver import MCPServer

from mcp.server.fastmcp import FastMCP
# from config import AWS_REGION

# --------------------------------------------------
# MCP SERVER
# --------------------------------------------------

mcp = FastMCP(
    "secure-ai-security",
    instructions="""
    Read-only AWS security investigation tools.

    These tools can inspect AWS security data.
    They do not perform destructive actions.
    """
)


# --------------------------------------------------
# AWS CLIENTS
# --------------------------------------------------


ec2 = boto3.client(
    "ec2",
    region_name="us-east-1"
)

cloudtrail = boto3.client(
    "cloudtrail",
    region_name="us-east-1"
)

guardduty = boto3.client(
    "guardduty",
    region_name="us-east-1"
)


# --------------------------------------------------
# EC2 TOOL
# --------------------------------------------------

@mcp.tool()
def get_ec2_instance(
    instance_id: str
) -> dict:
    """
    Get read-only information about an EC2 instance.

    Use this when investigating:
    - suspicious EC2 activity
    - compromised instances
    - instance state
    - network information
    """

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
            "message": "EC2 instance not found"
        }

    instance = reservations[0][
        "Instances"
    ][0]

    return {
        "found": True,
        "instance_id": instance.get(
            "InstanceId"
        ),
        "state": instance.get(
            "State",
            {}
        ).get("Name"),
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
        )
    }


# --------------------------------------------------
# CLOUDTRAIL TOOL
# --------------------------------------------------

@mcp.tool()
def get_cloudtrail_events(
    username: str = "",
    resource_name: str = "",
    max_results: int = 10
) -> list:
    """
    Search recent CloudTrail events.

    Use this to investigate:
    - IAM activity
    - EC2 API activity
    - suspicious AWS API calls
    - resource activity
    """

    max_results = min(
        max(max_results, 1),
        50
    )

    kwargs = {
        "MaxResults": max_results
    }

    if username:

        kwargs["LookupAttributes"] = [
            {
                "AttributeKey": "Username",
                "AttributeValue": username
            }
        ]

    elif resource_name:

        kwargs["LookupAttributes"] = [
            {
                "AttributeKey": "ResourceName",
                "AttributeValue": resource_name
            }
        ]

    response = cloudtrail.lookup_events(
        **kwargs
    )

    events = []

    for event in response.get(
        "Events",
        []
    ):

        events.append({
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
            )
        })

    return events


# --------------------------------------------------
# GUARDDUTY TOOL
# --------------------------------------------------

@mcp.tool()
def get_guardduty_findings(
    detector_id: str,
    finding_ids: list[str]
) -> list:
    """
    Retrieve GuardDuty finding details.

    Use this when a security alert references
    a GuardDuty finding.
    """

    response = guardduty.get_findings(
        DetectorId=detector_id,
        FindingIds=finding_ids
    )

    findings = []

    for finding in response.get(
        "Findings",
        []
    ):

        findings.append({
            "id": finding.get("Id"),
            "type": finding.get("Type"),
            "title": finding.get("Title"),
            "description": finding.get(
                "Description"
            ),
            "severity": finding.get(
                "Severity"
            ),
            "region": finding.get(
                "Region"
            )
        })

    return findings


# --------------------------------------------------
# START SERVER
# --------------------------------------------------

if __name__ == "__main__":

    mcp.run(
        transport="streamable-http"
    )
