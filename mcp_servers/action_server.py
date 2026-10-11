import os
import re
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP


# ============================================================
# Environment
# ============================================================

load_dotenv()

AWS_REGION = os.getenv(
    "AWS_REGION",
    "us-east-1",
)


# ============================================================
# MCP Server
# ============================================================

mcp = FastMCP(
    "security-action-server",
    host="127.0.0.1",
    port=8001
)


# ============================================================
# AWS Clients
# ============================================================

ec2_client = boto3.client(
    "ec2",
    region_name=AWS_REGION,
)


# ============================================================
# Security Constants
# ============================================================

ALLOWED_ACTIONS = {
    "TAG_RESOURCE",
}

SUPPORTED_ACTIONS = {
    "TAG_RESOURCE",
    "ISOLATE_INSTANCE",
    "BLOCK_IP",
    "DISABLE_ACCESS_KEY",
}


# ============================================================
# Validation Helpers
# ============================================================

def validate_instance_id(
    instance_id: str,
) -> bool:
    """
    Validate AWS EC2 instance ID.

    Examples:
        i-0123456789abcdef0
        i-0123456789abcdef012
    """

    if not isinstance(instance_id, str):
        return False

    return bool(
        re.fullmatch(
            r"i-[0-9a-fA-F]{8,32}",
            instance_id,
        )
    )


def validate_tag_key(
    key: str,
) -> bool:
    """
    Basic AWS tag-key validation.
    """

    if not isinstance(key, str):
        return False

    if not key:
        return False

    if len(key) > 128:
        return False

    return True


def validate_tag_value(
    value: str,
) -> bool:
    """
    Basic AWS tag-value validation.
    """

    if not isinstance(value, str):
        return False

    if len(value) > 256:
        return False

    return True


# ============================================================
# Health Check
# ============================================================

@mcp.tool()
def action_health_check() -> dict[str, Any]:
    """
    Health check for the security action MCP server.
    """

    return {
        "status": "OK",
        "service": "security-action-server",
        "region": AWS_REGION,
        "supported_actions": sorted(
            SUPPORTED_ACTIONS
        ),
        "enabled_actions": sorted(
            ALLOWED_ACTIONS
        ),
    }


# ============================================================
# Get Supported Actions
# ============================================================

@mcp.tool()
def get_supported_actions() -> dict[str, Any]:
    """
    Return supported and currently enabled actions.
    """

    return {
        "supported_actions": sorted(
            SUPPORTED_ACTIONS
        ),
        "enabled_actions": sorted(
            ALLOWED_ACTIONS
        ),
        "disabled_actions": sorted(
            SUPPORTED_ACTIONS - ALLOWED_ACTIONS
        ),
    }


# ============================================================
# Tag EC2 Resource
# ============================================================

@mcp.tool()
def tag_ec2_instance(
    instance_id: str,
    tag_key: str,
    tag_value: str,
) -> dict[str, Any]:
    """
    Apply an AWS tag to an EC2 instance.

    This is currently the only enabled write action.

    Example:

        instance_id = i-0123456789abcdef0
        tag_key     = SecurityAction
        tag_value   = AI-REMEDIATED
    """

    # --------------------------------------------------------
    # Validate instance
    # --------------------------------------------------------

    if not validate_instance_id(
        instance_id
    ):
        return {
            "status": "ERROR",
            "error": "INVALID_INSTANCE_ID",
            "message": (
                "Invalid EC2 instance ID."
            ),
        }

    # --------------------------------------------------------
    # Validate tag key
    # --------------------------------------------------------

    if not validate_tag_key(
        tag_key
    ):
        return {
            "status": "ERROR",
            "error": "INVALID_TAG_KEY",
            "message": (
                "Invalid AWS tag key."
            ),
        }

    # --------------------------------------------------------
    # Validate tag value
    # --------------------------------------------------------

    if not validate_tag_value(
        tag_value
    ):
        return {
            "status": "ERROR",
            "error": "INVALID_TAG_VALUE",
            "message": (
                "Invalid AWS tag value."
            ),
        }

    # --------------------------------------------------------
    # AWS operation
    # --------------------------------------------------------

    try:

        ec2_client.create_tags(
            Resources=[
                instance_id
            ],
            Tags=[
                {
                    "Key": tag_key,
                    "Value": tag_value,
                }
            ],
        )

        return {
            "status": "SUCCESS",
            "action": "TAG_RESOURCE",
            "resource_id": instance_id,
            "tag": {
                "key": tag_key,
                "value": tag_value,
            },
            "message": (
                "EC2 instance tag applied successfully."
            ),
        }

    except ClientError as exc:

        error = exc.response.get(
            "Error",
            {},
        )

        return {
            "status": "ERROR",
            "error": error.get(
                "Code",
                "AWS_CLIENT_ERROR",
            ),
            "message": error.get(
                "Message",
                str(exc),
            ),
        }

    except BotoCoreError as exc:

        return {
            "status": "ERROR",
            "error": "AWS_CORE_ERROR",
            "message": str(exc),
        }

    except Exception as exc:

        return {
            "status": "ERROR",
            "error": "INTERNAL_ERROR",
            "message": str(exc),
        }


# ============================================================
# Explicitly Disabled Actions
# ============================================================

@mcp.tool()
def execute_security_action(
    action: str,
    resource_id: str,
) -> dict[str, Any]:
    """
    Generic security action entry point.

    Only TAG_RESOURCE is currently enabled.

    Destructive actions are intentionally blocked until
    their individual implementations and safety controls
    are added.
    """

    if action not in SUPPORTED_ACTIONS:

        return {
            "status": "ERROR",
            "error": "UNSUPPORTED_ACTION",
            "message": (
                f"Unsupported security action: {action}"
            ),
        }

    if action not in ALLOWED_ACTIONS:

        return {
            "status": "DENIED",
            "error": "ACTION_DISABLED",
            "action": action,
            "resource_id": resource_id,
            "message": (
                f"Action '{action}' is currently disabled."
            ),
        }

    # --------------------------------------------------------
    # TAG_RESOURCE
    # --------------------------------------------------------

    if action == "TAG_RESOURCE":

        if not validate_instance_id(
            resource_id
        ):
            return {
                "status": "ERROR",
                "error": "INVALID_RESOURCE_ID",
                "message": (
                    "TAG_RESOURCE currently requires "
                    "a valid EC2 instance ID."
                ),
            }

        return {
            "status": "READY",
            "action": "TAG_RESOURCE",
            "resource_id": resource_id,
            "message": (
                "Resource is ready for tagging. "
                "Use tag_ec2_instance to perform the "
                "actual tag operation."
            ),
        }

    return {
        "status": "ERROR",
        "error": "UNHANDLED_ACTION",
        "message": (
            "Action was not handled."
        ),
    }


# ============================================================
# Server Entry Point
# ============================================================

if __name__ == "__main__":

    print(
        "Starting Security Action MCP Server..."
    )

    print(
        f"AWS Region: {AWS_REGION}"
    )

    print(
        "Enabled actions:",
        sorted(ALLOWED_ACTIONS),
    )

    print(
        "MCP endpoint: "
        "http://127.0.0.1:8001/mcp"
    )

    mcp.run(
        transport="streamable-http"
    )