from graph.workflow import graph


alert = {
    "alert_type": "GuardDuty",
    "severity": "HIGH",
    "source_ip": "185.10.20.30",
    "instance_id": "i-0123456789",
    "description": (
        "Suspicious activity detected "
        "against EC2 instance"
    )
}


result = graph.invoke({
    "alert": alert
})


print("\n")
print("=" * 70)
print("SECURE AI AGENT RESULT")
print("=" * 70)

print("\nRisk:")
print(result.get("risk"))

print("\nConfidence:")
print(result.get("confidence"))

print("\nFindings:")

for finding in result.get(
    "findings",
    []
):
    print("-", finding)

print("\nRecommended Action:")
print(
    result.get(
        "recommended_action"
    )
)

print("\nRequires Approval:")
print(
    result.get(
        "requires_approval"
    )
)

print("\nEvidence:")

for evidence in result.get(
    "evidence",
    []
):
    print(evidence)