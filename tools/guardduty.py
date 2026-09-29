import boto3

from langchain_core.tools import tool


guardduty = boto3.client(
    "guardduty",
    region_name="us-east-1"
)


@tool
def get_guardduty_findings(
    detector_id: str,
    finding_ids: list[str]
) -> list:
    """
    Retrieve GuardDuty finding details.

    Use this tool when a security alert
    references a GuardDuty finding.
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
            ),
            "service": finding.get(
                "Service"
            )
        })

    return findings