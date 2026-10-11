import os
import re
import logging
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP


# ============================================================
# Environment
# ============================================================

load_dotenv()

AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

# Comma-separated list of explicitly authorized EC2 instance IDs.
# Example:
# SECURE_AI_ALLOWED_INSTANCE_IDS=i-0123456789abcdef0
#
# Empty by default => all EC2 tag writes are denied.

ALLOWED_EC2_INSTANCE_IDS = {
    item.strip()
    for item in os.getenv(
        "SECURE_AI_ALLOWED_INSTANCE_IDS",
        "",
    ).split(",")
    if item.strip()
}

# Do not log credentials, secrets, or complete environment values.
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================
# MCP Server
# ============================================================

mcp = FastMCP(
    "security-action-server",
    host="127.0.0.1",
    port=8001,
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

# Only this action is currently enabled.
ALLOWED_ACTIONS = {
    "TAG_RESOURCE",
}

# Known actions; the other actions remain disabled.
SUPPORTED_ACTIONS = {
    "TAG_RESOURCE",
    "ISOLATE_INSTANCE",
    "BLOCK_IP",
    "DISABLE_ACCESS_KEY",
}

INSTANCE_ID_PATTERN = re.compile(
    r"i-[0-9a-fA-F]{8,32}"
)


# ============================================================
# Validation Helpers
# ============================================================

def validate_instance_id(instance_id: str) -> bool:
    """Validate the format of an EC2 instance ID."""

    if not isinstance(instance_id, str):
        return False

    return bool(
        INSTANCE_ID_PATTERN.fullmatch(instance_id)
    )


def validate_tag_key(key: str) -> bool:
    """Validate an AWS tag key."""

    if not isinstance(key, str):
        return False

    if not key or len(key) > 128:
        return False

    # AWS reserves tag keys beginning with aws:.
    if key.lower().startswith("aws:"):
        return False

    # Reject control characters.
    if any(ord(char) < 32 or ord(char) == 127 for char in key):
        return False

    return True


def validate_tag_value(value: str) -> bool:
    """Validate an AWS tag value."""

    if not isinstance(value, str):
        return False

    if len(value) > 256:
        return False

    if any(
        ord(char) < 32 or ord(char) == 127
        for char in value
    ):
        return False

    return True


def is_instance_authorized(instance_id: str) -> bool:
    """
    Fail closed unless the EC2 instance is explicitly allowlisted.

    This is a resource allowlist, not tenant authentication.
    """

    if not validate_instance_id(instance_id):
        return False

    return instance_id in ALLOWED_EC2_INSTANCE_IDS


def error_response(
    code: str,
    message: str,
    *,
    resource_id: str | None = None,
) -> dict[str, Any]:
    """Build a consistent error response."""

    result: dict[str, Any] = {
        "status": "ERROR",
        "error": code,
        "message": message,
    }

    if resource_id is not None:
        result["resource_id"] = resource_id

    return result


def denied_response(
    code: str,
    message: str,
    *,
    action: str | None = None,
    resource_id: str | None = None,
) -> dict[str, Any]:
    """Build a consistent authorization-denied response."""

    result: dict[str, Any] = {
        "status": "DENIED",
        "error": code,
        "message": message,
    }

    if action is not None:
        result["action"] = action

    if resource_id is not None:
        result["resource_id"] = resource_id

    return result


# ============================================================
# Health Check
# ============================================================

@mcp.tool()
def action_health_check() -> dict[str, Any]:
    """Return basic health and security configuration status."""

    return {
        "status": "OK",
        "service": "security-action-server",
        "region": AWS_REGION,
        "supported_actions": sorted(SUPPORTED_ACTIONS),
        "enabled_actions": sorted(ALLOWED_ACTIONS),
        "resource_allowlist_configured": bool(
            ALLOWED_EC2_INSTANCE_IDS
        ),
        "allowlisted_resource_count": len(
            ALLOWED_EC2_INSTANCE_IDS
        ),
    }


# ============================================================
# Get Supported Actions
# ============================================================

@mcp.tool()
def get_supported_actions() -> dict[str, Any]:
    """Return supported, enabled, and disabled actions."""

    return {
        "supported_actions": sorted(SUPPORTED_ACTIONS),
        "enabled_actions": sorted(ALLOWED_ACTIONS),
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
    Apply a tag to an explicitly allowlisted EC2 instance.

    This is the only enabled AWS write operation.

    No instance is authorized by default. Configure
    SECURE_AI_ALLOWED_INSTANCE_IDS before using this tool.
    """

    # --------------------------------------------------------
    # 1. Validate instance ID
    # --------------------------------------------------------

    if not validate_instance_id(instance_id):
        return error_response(
            "INVALID_INSTANCE_ID",
            "Invalid EC2 instance ID.",
        )

    # --------------------------------------------------------
    # 2. Validate tag key
    # --------------------------------------------------------

    if not validate_tag_key(tag_key):
        return error_response(
            "INVALID_TAG_KEY",
            "Invalid AWS tag key.",
            resource_id=instance_id,
        )

    # --------------------------------------------------------
    # 3. Validate tag value
    # --------------------------------------------------------

    if not validate_tag_value(tag_value):
        return error_response(
            "INVALID_TAG_VALUE",
            "Invalid AWS tag value.",
            resource_id=instance_id,
        )

    # --------------------------------------------------------
    # 4. Independent resource authorization boundary
    # --------------------------------------------------------

    if "TAG_RESOURCE" not in ALLOWED_ACTIONS:
        return denied_response(
            "ACTION_DISABLED",
            "TAG_RESOURCE is currently disabled.",
            action="TAG_RESOURCE",
            resource_id=instance_id,
        )

    if not is_instance_authorized(instance_id):
        logger.warning(
            "Tag action denied: resource is not allowlisted."
        )

        return denied_response(
            "RESOURCE_NOT_AUTHORIZED",
            (
                "EC2 instance is not in the configured resource "
                "allowlist. No AWS write was executed."
            ),
            action="TAG_RESOURCE",
            resource_id=instance_id,
        )

    # --------------------------------------------------------
    # 5. AWS write — only after validation and authorization
    # --------------------------------------------------------

    try:
        ec2_client.create_tags(
            Resources=[instance_id],
            Tags=[
                {
                    "Key": tag_key,
                    "Value": tag_value,
                }
            ],
        )

        logger.info(
            "EC2 tag operation succeeded for an authorized resource."
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
        error = exc.response.get("Error", {})
        error_code = error.get(
            "Code",
            "AWS_CLIENT_ERROR",
        )

        # Log only the error code; do not expose AWS details
        # or infrastructure information to the calling agent.
        logger.error(
            "EC2 tag operation failed. AWS error code: %s",
            error_code,
        )

        return error_response(
            error_code,
            "AWS rejected the tag operation or the operation failed.",
            resource_id=instance_id,
        )

    except BotoCoreError:
        logger.exception(
            "AWS SDK transport or core error during tag operation."
        )

        return error_response(
            "AWS_CORE_ERROR",
            "AWS SDK operation failed.",
            resource_id=instance_id,
        )

    except Exception:
        logger.exception(
            "Unexpected error during EC2 tag operation."
        )

        return error_response(
            "INTERNAL_ERROR",
            "Unexpected internal error.",
            resource_id=instance_id,
        )


# ============================================================
# Generic Security Action Entry Point
# ============================================================

@mcp.tool()
def execute_security_action(
    action: str,
    resource_id: str,
) -> dict[str, Any]:
    """
    Validate a generic security action request.

    This function does not perform the AWS write.
    TAG_RESOURCE returns READY only when the resource is
    allowlisted. Use tag_ec2_instance for the actual write.
    """

    # --------------------------------------------------------
    # 1. Validate action
    # --------------------------------------------------------

    if not isinstance(action, str):
        return error_response(
            "INVALID_ACTION",
            "Action must be a string.",
        )

    if action not in SUPPORTED_ACTIONS:
        return error_response(
            "UNSUPPORTED_ACTION",
            "The requested security action is unsupported.",
        )

    # --------------------------------------------------------
    # 2. Disabled actions are always denied
    # --------------------------------------------------------

    if action not in ALLOWED_ACTIONS:
        return denied_response(
            "ACTION_DISABLED",
            f"Action '{action}' is currently disabled.",
            action=action,
            resource_id=resource_id
            if isinstance(resource_id, str)
            else None,
        )

    # --------------------------------------------------------
    # 3. Handle TAG_RESOURCE
    # --------------------------------------------------------

    if action == "TAG_RESOURCE":

        if not validate_instance_id(resource_id):
            return error_response(
                "INVALID_RESOURCE_ID",
                (
                    "TAG_RESOURCE currently requires "
                    "a valid EC2 instance ID."
                ),
            )

        if not is_instance_authorized(resource_id):
            return denied_response(
                "RESOURCE_NOT_AUTHORIZED",
                (
                    "EC2 instance is not in the configured "
                    "resource allowlist."
                ),
                action=action,
                resource_id=resource_id,
            )

        return {
            "status": "READY",
            "action": "TAG_RESOURCE",
            "resource_id": resource_id,
            "message": (
                "Resource passed the local action and resource "
                "checks. This response does not execute an AWS write."
            ),
        }

    return error_response(
        "UNHANDLED_ACTION",
        "Action was not handled.",
    )


# ============================================================
# Server Entry Point
# ============================================================

if __name__ == "__main__":
    print("Starting Security Action MCP Server...")
    print(f"AWS Region: {AWS_REGION}")
    print("Enabled actions:", sorted(ALLOWED_ACTIONS))
    print(
        "Resource allowlist configured:",
        bool(ALLOWED_EC2_INSTANCE_IDS),
    )
    print(
        "MCP endpoint: http://127.0.0.1:8001/mcp"
    )

    mcp.run(
        transport="streamable-http"
    )
