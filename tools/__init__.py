from tools.cloudtrail import (
    get_cloudtrail_events
)

from tools.guardduty import (
    get_guardduty_findings
)

from tools.ec2 import (
    get_ec2_instance
)


TOOLS = [
    get_cloudtrail_events,
    get_guardduty_findings,
    get_ec2_instance
]