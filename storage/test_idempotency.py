
from botocore.exceptions import ClientError
from unittest.mock import MagicMock

from storage.idempotency import (
    IdempotencyStore,
    IdempotencyConflict,
    IdempotencyAlreadyCompleted,
)


def main():
    store = IdempotencyStore.__new__(IdempotencyStore)
    store.table = MagicMock()

    key = "default:INC-TEST-001:TAG_RESOURCE:i-mock123"

    # Test 1: First request claims the key.
    print("Test 1: First claim")

    store.table.put_item.return_value = {}

    store.claim(
        idempotency_key=key,
        incident_id="INC-TEST-001",
        tenant_id="default",
        action="TAG_RESOURCE",
        resource_id="i-mock123",
    )

    store.table.put_item.assert_called_once()
    print("PASS: First claim succeeded.")

    # Test 2: Existing IN_PROGRESS request causes conflict.
    print("\nTest 2: Duplicate in-progress claim")

    
    store.table.put_item.side_effect = ClientError(
        {
            "Error": {
                "Code": "ConditionalCheckFailedException",
                "Message": "The conditional request failed",
            }
        },
        "PutItem",
    )


    store.table.get_item.return_value = {
        "Item": {
            "idempotency_key": key,
            "status": "IN_PROGRESS",
        }
    }

    try:
        store.claim(
            idempotency_key=key,
            incident_id="INC-TEST-001",
            tenant_id="default",
            action="TAG_RESOURCE",
            resource_id="i-mock123",
        )
    except IdempotencyConflict:
        print("PASS: Duplicate in-progress claim rejected.")
    else:
        raise AssertionError("Expected IdempotencyConflict")

    # Test 3: Existing SUCCESS returns prior result.
    print("\nTest 3: Completed request replay")

    previous_result = {
        "status": "SUCCESS",
        "message": "Previously completed",
    }

    store.table.get_item.return_value = {
        "Item": {
            "idempotency_key": key,
            "status": "SUCCESS",
            "result": previous_result,
        }
    }

    try:
        store.claim(
            idempotency_key=key,
            incident_id="INC-TEST-001",
            tenant_id="default",
            action="TAG_RESOURCE",
            resource_id="i-mock123",
        )
    except IdempotencyAlreadyCompleted as exc:
        print("PASS: Completed request recognized.")
        print("Previous result:", exc.result)
        assert exc.result == previous_result
    else:
        raise AssertionError(
            "Expected IdempotencyAlreadyCompleted"
        )

    print("\nAll idempotency tests completed.")


if __name__ == "__main__":
    main()
