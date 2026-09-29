import boto3

from langchain_core.tools import tool


ec2 = boto3.client(
    "ec2",
    region_name="us-east-1"
)


@tool
def get_ec2_instance(
    instance_id: str
) -> dict:
    """
    Get EC2 instance information.

    Use this tool when investigating
    an EC2 security incident.
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
            "message": "Instance not found"
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