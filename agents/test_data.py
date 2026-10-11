import os

from dotenv import load_dotenv


load_dotenv()


def build_test_alert():
    """
    Build a test security alert using real AWS identifiers.

    Required .env variables:

        TEST_EC2_INSTANCE_ID
        TEST_GUARDDUTY_DETECTOR_ID
        TEST_GUARDDUTY_FINDING_ID

    GuardDuty identifiers are optional because an alert
    may not always contain GuardDuty information.
    """

    instance_id = os.getenv(
        "TEST_EC2_INSTANCE_ID"
    )

    detector_id = os.getenv(
        "TEST_GUARDDUTY_DETECTOR_ID"
    )

    finding_id = os.getenv(
        "TEST_GUARDDUTY_FINDING_ID"
    )

    # EC2 instance ID is required for this test scenario.
    if not instance_id:
        raise ValueError(
            "TEST_EC2_INSTANCE_ID is missing from .env"
        )

    alert = {
        "alert_id": "ALT-TEST-001",

        "source": "GuardDuty",

        "severity": "HIGH",

        "title": "Suspicious EC2 activity",

        "description": (
            "Test security alert for investigating "
            "suspicious activity on an EC2 instance."
        ),

        "instance_id": instance_id,

        "guardduty_detector_id": detector_id,

        "guardduty_finding_id": finding_id,
    }

    return alert