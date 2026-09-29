import boto3

from langchain_core.tools import tool


cloudtrail = boto3.client(
    "cloudtrail",
    region_name="us-east-1"
)


@tool
def get_cloudtrail_events(
    username: str = None,
    resource_name: str = None,
    max_results: int = 10
) -> list:
    """
    Search recent AWS CloudTrail events.

    Use this tool when investigating:
    - IAM activity
    - EC2 API activity
    - suspicious AWS API calls
    - account activity
    """

    kwargs = {
        "MaxResults": min(max_results, 50)
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